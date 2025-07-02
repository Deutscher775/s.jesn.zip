import fastapi
from fastapi import middleware
import uvicorn
import json
import random
import pathlib
import os
import string
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import threading
import time
import mimetypes
import subprocess
from fastapi import UploadFile, File, Form
import re
import queue
from fastapi.responses import StreamingResponse


random_words = list(set([
    "apple", "grape", "peach", "plum", "berry", "melon", "lemon", "mango", "olive", "pearl",
    "stone", "flame", "blaze", "spark", "ember", "glow", "shine", "chickenjokey", "gleam", "flash", "flare",
    "storm", "cloud", "rainy", "sunny", "windy", "breez", "lol", "frost", "snowy", "chill", "blizz",
    "mount", "ridge", "69", "valle", "plain", "field", "ligma", "meado", "grove", "woods", "forest", "jungle",
    "river", "creek", "brook", "stream", "ocean", "beach", "shore", "coast", "islan", "coral",
    "eagle", "hawk", "jesn", "L347", "falco", "robin", "sparr", "finch", "swall", "heron", "crane", "stork",
    "tiger", "lion", "leopa", "cheet", "puma", "jagua", "lynx", "couga", "420", "panth", "ocelo",
    "horse", "zebra", "donke", "mule", "camel", "sheep", "goat", "ram", "nahundgut",
    "whale", "dolph", "shark", "ray", "eel", "octop", "squid", "crab", "lobster", "shrimp",
    "banana", "kiwi", "papaya", "guava", "fig", "date", "quince", "apricot",
    "volcano", "geyser", "canyon", "cliff", "dune", "glacier", "hill", "mesa", "plateau", "valley",
    "falcon", "owl", "parrot", "pigeon", "crow", "raven",
    "bear", "wolf", "fox", "otter", "weasel", "badger", "ferret",
    "bison", "yak", "gazelle", "ibex", "moose", "caribou", "elk",
    "seal", "walrus", "narwhal", "l347", "orca", "beluga", "penguin"
    "school", "college", "university", "academy", "institute", "center", "lab", "library", "museum", "gallery",
    "garden", "park", "zoo", "theater", "cinema", "studio", "station",
    "circle", "square", "plaza", "court", "ao","lane", "drive", "way", "path", "trail", "track",
    "pizza", "pasta", "burger", "taco", "burrito", "sushi", "ramen", "pho", "curry", "kebab",
    "coffee", "tea", "juice", "soda", "beer", "wine", "whisky", "vodka", "rum", "gin",
    "cake", "cookie", "pie", "pudding", "candy", "chocolate", "caramel", "fudge", "jelly"
]))

# Dictionary to track conversion progress
conversion_progress = {}

app = fastapi.FastAPI()

# Middleware to limit the request size
class LimitRequestSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        max_request_size = 500 * 1024 * 1024  # 500 MB upload limit
        if request.headers.get("content-length") and int(request.headers["content-length"]) > max_request_size:
            return fastapi.responses.JSONResponse(status_code=413, content={"error": "Payload Too Large"})
        return await call_next(request)

app.add_middleware(LimitRequestSizeMiddleware)


@app.get("/")
def read_root():
    return fastapi.responses.RedirectResponse(url="/create", status_code=302)

@app.get("/create")
def render_create_webinterface():
    return fastapi.responses.HTMLResponse(content=open("./webinterface/create.html", "r").read())

@app.get("/privacy.html")
def render_privacy_html():
    return fastapi.responses.HTMLResponse(content=open("./webinterface/privacy.html", "r").read())

@app.get("/privacy")
def render_privacy_webinterface():
    return fastapi.responses.HTMLResponse(content=open("./webinterface/privacy.html", "r").read())

@app.get("/imprint")
def render_imprint_webinterface():
    return fastapi.responses.RedirectResponse(url="https://astroid.cc/imprint", status_code=302)

@app.get("/{share_path}")
def read_share(share_path: str):
    shares_file = open("urls.txt", "r")
    shares = shares_file.readlines()
    for share in shares:
        share = share.strip()
        if share_path in share:
            share = share.split(";")
            return fastapi.responses.RedirectResponse(url=share[1], status_code=302)
    return fastapi.responses.JSONResponse(status_code=404, content={"error": "Share not found"})
    
@app.post("/api/shorten")
async def shorten_url(request: fastapi.Request):
    request_body = await request.json()
    origin = request_body["origin"]
    url = request_body["url"]
    linkfile = open("urls.txt", "r+")
    links = linkfile.readlines()
    if url in links:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "URL already shortened"})
    unique_id = random.choices(string.ascii_letters + string.digits, k=6) # Possible characters: a-z, A-Z, 0-9, length: 6
    unique_id = random.choices(unique_id, k=3)
    unique_id = "".join(unique_id)
    random_word = random.choice(random_words)
    unique_id = random_word + unique_id
    share_path = f"{origin}/{unique_id}"
    if share_path in links:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "URL taken. Please try again."})
    linkfile.write(f"{share_path};{url}\n")
    return fastapi.responses.JSONResponse(status_code=201, content={"url": share_path, "original_url": url})

def stipFFmpegDebug(line):
    """
    Entfernt sensible Pfade und Usernamen aus einer FFmpeg-Debug-Zeile.
    """
    # Windows-Pfade (z.B. C:\Users\jason\... oder D:\irgendwas\...)
    line = re.sub(r"[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]*", "<PATH>", line)
    # Unix-Pfade (z.B. /home/user/..., /tmp/..., /irgendwas)
    line = re.sub(r"/(?:[^/\s]+/)*[^/\s]*", "<PATH>", line)
    # Usernamen in Windows-Pfaden maskieren (z.B. C:\Users\jason -> C:\Users\<USER>)
    line = re.sub(r"C:\\Users\\[^\\\s]+", r"C:\\Users\\<USER>", line)
    # Usernamen in Linux-Pfaden maskieren (z.B. /home/jason -> /home/<USER>)
    line = re.sub(r"/home/[^/\s]+", r"/<USER>/", line)
    # Usernamen in /root/... Pfaden maskieren (z.B. /root/.cache -> /root/<USER>)
    line = re.sub(r"/root/[^/\s]+", r"/<USER>/", line)
    return line


def ffmpeg_convert(input_path, output_path, share_path):
    q = conversion_progress[share_path]
    cmd = [
        "ffmpeg",
        "-analyzeduration", "100M",
        "-probesize", "100M",
        "-y",
        "-i", input_path,
        output_path
    ]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    duration = None
    for line in process.stderr:
        clean_line = stipFFmpegDebug(line)
        print(line, end="")  # Print FFmpeg output live to console
        # Gesamtdauer extrahieren
        if duration is None:
            match = re.search(r"Duration: (\d+):(\d+):(\d+\.\d+)", line)
            if match:
                h, m, s = match.groups()
                duration = int(h) * 3600 + int(m) * 60 + float(s)
        # Fortschritt extrahieren
        match = re.search(r"time=(\d+):(\d+):(\d+\.\d+)", line)
        if match and duration:
            h, m, s = match.groups()
            current = int(h) * 3600 + int(m) * 60 + float(s)
            percent = (current / duration) * 100
            eta = (duration - current)
            # Fortschritt in Queue speichern
            q.put({"percent": percent, "eta": eta, "debug": clean_line, "finished": False})
    process.wait()
    q.put({"percent": 100, "eta": 0, "finished": True, "share_path": share_path})

@app.post("/api/convert")
async def convert_to_share(
    file: UploadFile = File(...),
    output_ext: str = Form(...),
    origin: str = Form(None)
):
    random_word = random.choice(random_words)
    input_filename = file.filename
    filename_wo_ext = ".".join(input_filename.strip().split(".")[:-1]) or input_filename
    share_path = f"{random_word}/{filename_wo_ext}.{output_ext}"
    input_file_path = f"{pathlib.Path(__file__).parent.resolve()}/uploads/JESNZIP_CONV_INPUT__{input_filename}"
    output_file_path = f"{pathlib.Path(__file__).parent.resolve()}/uploads/{filename_wo_ext}.{output_ext}"

    with open(input_file_path, "wb") as f:
        f.write(await file.read())

    # Fortschritts-Queue anlegen
    q = queue.Queue()
    conversion_progress[share_path] = q
    print(conversion_progress)

    # FFmpeg-Konvertierung im Thread starten
    threading.Thread(target=ffmpeg_convert, args=(input_file_path, output_file_path, share_path), daemon=True).start()

    file_url = f"{origin}/u/{random_word}/{filename_wo_ext}.{output_ext}"
    with open("files.txt", "a+") as file_file:
        file_file.write(f"{file_url};{output_file_path}\n")

    return fastapi.responses.JSONResponse(
        status_code=201,
        content={"share_url": file_url, "share_path": share_path, "conversion_started": True}
    )

@app.get("/api/convert_progress/{share_path:path}")
async def convert_progress(share_path: str):
    if "%2F" in share_path:
        share_path = share_path.replace("%2F", "/")
    async def event_generator():
        q = conversion_progress.get(share_path)
        if not q:
            yield f"data: {json.dumps({'percent': 0, 'eta': None, 'error': 'No conversion'})}\n\n"
            return
        while True:
            try:
                progress = q.get(timeout=30)
                yield f"data: {json.dumps(progress)}\n\n"
                if progress.get("finished"):
                    break
            except queue.Empty:
                break
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.delete("/{share_path}")
def delete_share(share_path: str):
    shares_file = open("shares.json", "r")
    shares = json.load(shares_file)

    if share_path in shares:
        del shares[share_path]
        shares_file = open("shares.json", "w")
        json.dump(shares, shares_file)
        shares_file.close()
        return fastapi.responses.JSONResponse(status_code=200, content={"message": "Share deleted", "share_path": share_path})
    else:
        return fastapi.responses.JSONResponse(status_code=404, content={"error": "Share not found"})
    
@app.get("/webinterface/create.js")
def render_create_js():
    if not os.path.exists(f"{pathlib.Path(__file__).parent.resolve()}/webinterface/create.js"):
        return fastapi.responses.JSONResponse(status_code=404, content={"error": "create.js not found"})
    # Serve the create.js file from the webinterface directory
    return fastapi.responses.FileResponse(f"{pathlib.Path(__file__).parent.resolve()}/webinterface/create.js")

@app.get("/u/{random_word}/{file_path}")
def download_file(random_word: str, file_path: str, download: bool = False):
    file_path = random_word + "/" + file_path
    file_file = open("files.txt", "r")
    files = file_file.readlines()
    for file in files:
        file = file.strip()
        if file_path in file:
            file = file.split(";")
            file_path_on_disk = file[1]
            with open(file_path_on_disk, "rb") as file_file:
                file_content = file_file.read()
            mimetype, _ = mimetypes.guess_type(file_path_on_disk)
            if download:
                return fastapi.responses.FileResponse(
                    path=file_path_on_disk,
                    media_type=mimetype,
                    filename=os.path.basename(file_path_on_disk),
                    headers={"Content-Disposition": f'attachment; filename="{os.path.basename(file_path_on_disk)}"'}
                )
            else:
                return fastapi.responses.Response(content=file_content, media_type=mimetype)
    return fastapi.responses.JSONResponse(status_code=404, content={"error": "File not found"})


@app.post("/api/upload")
async def upload_file(request: fastapi.Request):
    request_body = await request.body()
    form = await request.form()
    file = form["file"]
    unique_id = random.choices(string.ascii_letters + string.digits, k=6) # Possible characters: a-z, A-Z, 0-9, length: 6
    unique_id = random.choices(unique_id, k=3)
    unique_id = "".join(unique_id)
    origin = request.headers["origin"]
    random_word = random.choice(random_words)
    file_url = f"{origin}/u/{random_word}/{file.filename.strip()}"
    file_path = f"./uploads/{file.filename.strip()}"
    file_file = open("files.txt", "r+")
    files = file_file.readlines()
    if file_url in files:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "File already uploaded"})
    file_file.write(f"{file_url};{file_path}\n")
    with open(file_path, "wb") as file_object:
        file_object.write(file.file.read())
    return fastapi.responses.JSONResponse(status_code=201, content={"url": file_url, "original_filename": file.filename.strip()})

def check_upload_worker():
    while True:
        files_file = open("files.txt", "r")
        files = files_file.readlines()
        files_file.close()
        updated_files = []
        for file in files:
            print(f"[FileChecker] Checking file: {file}")
            file = file.strip()
            file_path = file.split(";")[1]
            if os.path.exists(file_path):
                updated_files.append(file + "\n")
            else:
                print(f"[FileChecker] Removed file: {file}")
        files_file = open("files.txt", "w")
        files_file.writelines(updated_files)
        files_file.close()
        time.sleep(300)

def start_workers():
    threading.Thread(target=check_upload_worker, daemon=True).start()

start_workers()

uvicorn.run(app, host="localhost", port=9941)
