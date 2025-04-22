window.onload = function() {
  document.getElementById("copyshortenedsvg").addEventListener("click", function() {
    copyText("shortened");
  });
  document.getElementById("copyfileurlsvg").addEventListener("click", function() {
    copyText("fileurl");
  });
  document.getElementById("fileUrlContainer").addEventListener("click", function() {
    copyText("fileurl");
  });
}


function shortenUrl() {
    document.getElementById("shortUrlContainer").classList.add("hidden"); 
    document.getElementById("jsonResponseContainer").classList.add("hidden");
    var link = document.getElementById("urlInput").value;
    if (link == "") {
        return raiseError("*insert nothing*", "Nothing is as short as it can get. Enter an URL to shorten it.");
    }
    if (!link.startsWith("http://") && !link.startsWith("https://")) {
        return raiseError("Huhttp?", "An URL without a protocol? Really?");
    }
    if (link.includes(" ")) {
      return raiseError("Space? No space!", "An URL with a space? The space is really really big, but not in an URL.");
    }
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/shorten", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function() {
      if (xhr.readyState == 4) {
        if (xhr.status == 201) {
          var response = JSON.parse(xhr.responseText);
          console.log(response);
          if (response.url) {
            document.getElementById("shortened").innerText = response.url;
            document.getElementById("shortUrlContainer").classList.remove("hidden");
          } else {
            document.getElementById("jsonResponse").innerText = JSON.stringify(response, null, 2);
            document.getElementById("jsonResponseContainer").classList.remove("hidden");
            console.error(response);
          }
        } else {
          alert("Failed to shorten URL. Status: " + xhr.status);
        }
      }
    };
    xhr.send(JSON.stringify({ origin: window.origin, url: link }));
}

function copyText(id) {
    var copyElement = document.getElementById(id);
    console.log(copyElement.id);
    navigator.clipboard
      	.writeText(copyElement.innerText)
        .then(() => {
          copyElement.parentElement.style.backgroundColor = "#ccffcc";
        })
        .catch(err => {
          console.error("Failed to copy text: ", err);
          copyElement.parentElement.style.backgroundColor = "#ffcccc";
    });
}

function raiseError(title, message) {
  console.error(title + ": " + message);
  if (!title || !message) {
    console.error("Error: Title or message is missing.");
    document.getElementById("popup").classList.remove("hidden");
  } else {
    document.getElementById("popup").classList.remove("hidden");
    document.getElementById("err.message").innerText = message;
    document.getElementById("err.title").innerText = title;
  }
}

function closePopup() {
    document.getElementById("popup").classList.add("hidden");
}

function uploadFile() {
  var fileInput = document.getElementById("fileUpload");
  var file = fileInput.files[0];
  var formData = new FormData();
  formData.append("file", file);
  document.getElementById("uploadProgressContainer").classList.remove("hidden");
  document.getElementById("")
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/upload", true);

  xhr.upload.onprogress = function(event) {
      if (event.lengthComputable) {
            var percentComplete = (event.loaded / event.total) * 100;
            if (!xhr.upload.startTime) {
              xhr.upload.startTime = event.timeStamp;
            }
            var timeElapsed = (event.timeStamp - xhr.upload.startTime) / 1000; // time in seconds
            var speed = (event.loaded * 8) / (timeElapsed * 1024 * 1024); // speed in Mbit/s
            var estimatedTime = (event.total - event.loaded) / (event.loaded / timeElapsed); // estimated time in seconds

            var timeDisplay;
            if (estimatedTime < 60) {
              timeDisplay = estimatedTime.toFixed(0) + " sec";
            } else if (estimatedTime < 3600) {
              timeDisplay = (estimatedTime / 60).toFixed(0) + " min";
            } else {
              timeDisplay = (estimatedTime / 3600).toFixed(2) + " hours";
            }

            console.debug("Speed: " + speed.toFixed(1) + " Mbit/s | Time elapsed: " + timeElapsed + " s | Estimated time: " + timeDisplay);
            document.getElementById("uploadProgress").style.width = percentComplete + "%";
            document.getElementById("uploadProgressPercentage").innerHTML = Math.round(percentComplete) + "%";
            document.getElementById("estTime").innerText = timeDisplay;
      }
  };

  xhr.onreadystatechange = function() {
      if (xhr.readyState == 4) {
          if (xhr.status == 201) {
              var response = JSON.parse(xhr.responseText);
              document.getElementById("fileUrlContainer").classList.remove("hidden");
              document.getElementById("fileurl").innerText = response.url;
              document.getElementById("fileurl").innerHTML = "<a href='" + response.url + "'>" + response.url + "</a>";
              document.getElementById("uploadProgressContainer").classList.add("hidden");
          } else {
              raiseError("We've lost your package!", "Failed to upload file. Status: " + xhr.status);
          }
      }
  };

  xhr.send(formData);
}
