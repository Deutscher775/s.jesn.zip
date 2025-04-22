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
    return fastapi.responses.FileResponse("./webinterface/create.js")

@app.get("/u/{random_word}/{file_path}")
def download_file(random_word: str, file_path: str):
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
