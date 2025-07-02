let justOpenedFormatMenu = false;

window.onload = function () {
	console.log("Initializing page...");

	document
		.getElementById("copyshortenedsvg")
		.addEventListener("click", function () {
			copyText("shortened");
		});

	document
		.getElementById("fileUrlContainer")
		.addEventListener("click", function () {
			copyText("fileurl");
		});

	// File input event listeners für die neuen Container
	document.getElementById("fileUpload").addEventListener("change", function () {
		const file = this.files[0];
		const label = document.getElementById("fileUploadLabel");
		if (file) {
			label.textContent = file.name;
		} else {
			label.textContent = "No file selected";
		}
	});

	document
		.getElementById("convertFileInput")
		.addEventListener("change", function () {
			const file = this.files[0];
			const label = document.getElementById("convertFileLabel");
			if (file) {
				label.textContent = file.name;
			} else {
				label.textContent = "No file selected";
			}
		});

	// Initialisiere Drag & Drop mit Verzögerung
	setTimeout(() => {
		console.log("Initializing drag and drop...");
		initializeDragAndDrop();
	}, 100);

	// Initialisiere Format-Menü
	setTimeout(() => {
		console.log("Initializing format menu...");
		initializeFormatMenu();
	}, 150);

	// Debug-Test mit zusätzlicher Verzögerung
	setTimeout(() => {
		testDragAndDropSupport();
	}, 500);
};

// Vereinfachte und robuste Drag & Drop-Initialisierung
function initializeDragAndDrop() {
	console.log("Setting up drag and drop...");

	// File Upload Container
	const fileUploadContainer = document.getElementById("fileUploadContainer");
	const fileUploadInput = document.getElementById("fileUpload");

	if (fileUploadContainer && fileUploadInput) {
		console.log("Setting up file upload drag and drop");
		setupContainerDragAndDrop(
			fileUploadContainer,
			fileUploadInput,
			"fileUploadLabel",
			true
		);
	} else {
		console.error("File upload elements not found");
	}

	// File Convert Container
	const fileConvertContainer = document.getElementById("fileConvertContainer");
	const fileConvertInput = document.getElementById("convertFileInput");

	if (fileConvertContainer && fileConvertInput) {
		console.log("Setting up file convert drag and drop");
		setupContainerDragAndDrop(
			fileConvertContainer,
			fileConvertInput,
			"convertFileLabel",
			false
		);
	} else {
		console.error("File convert elements not found");
	}
}

function setupContainerDragAndDrop(container, input, labelId, autoUpload) {
	console.log("Setting up drag and drop for container:", container.id);

	// Globale Drag & Drop Prevention (nur einmal)
	if (!window.dragDropInitialized) {
		document.addEventListener("dragover", function (e) {
			e.preventDefault();
		});

		document.addEventListener("drop", function (e) {
			e.preventDefault();
		});

		window.dragDropInitialized = true;
	}

	// Container-spezifische Events
	container.addEventListener("dragenter", function (e) {
		e.preventDefault();
		e.stopPropagation();
		container.classList.add("drag-over");
		console.log("Drag enter on", container.id);
	});

	container.addEventListener("dragover", function (e) {
		e.preventDefault();
		e.stopPropagation();
		container.classList.add("drag-over");
	});

	container.addEventListener("dragleave", function (e) {
		e.preventDefault();
		e.stopPropagation();
		// Nur entfernen wenn wir den Container wirklich verlassen
		if (!container.contains(e.relatedTarget)) {
			container.classList.remove("drag-over");
		}
	});

	container.addEventListener("drop", function (e) {
		e.preventDefault();
		e.stopPropagation();
		container.classList.remove("drag-over");

		console.log("Drop event on", container.id);

		const files = e.dataTransfer.files;
		console.log("Files dropped:", files.length);

		if (files.length > 0) {
			const file = files[0];
			console.log("File:", file.name, "Size:", file.size, "Type:", file.type);
			if (file.size <= 0) {
				return raiseError("*crickets*", "Seems like you dropped an empty file. Please upload a non-empty file.");
			}
			else if (file.size > 500 * 1024 * 1024) {
				return raiseError(
					"File too large",
					"Please upload files smaller than 100 MB."
				);
			}

			// Update Label
			const label = document.getElementById(labelId);
			if (label) {
				label.textContent = file.name;
			}

			// Versuche files zu setzen
			try {
				const dt = new DataTransfer();
				dt.items.add(file);
				input.files = dt.files;
				console.log("Files set successfully");
			} catch (error) {
				console.warn("DataTransfer failed:", error);
			}

			// Upload ausführen
			if (autoUpload) {
				console.log("Auto-uploading file...");
				try {
					uploadFile();
				} catch (error) {
					console.error("Upload failed:", error);
					uploadFileWithFile(file);
				}
			}
		}
	});

	// Click-Handler für Container
	container.addEventListener("click", function (e) {
		// Verhindere dass der Click auf Labels oder SVGs den Dialog öffnet
		if (
			!e.target.closest("label") &&
			!e.target.closest("svg") &&
			e.target.tagName.toLowerCase() !== "p"
		) {
			console.log("Opening file dialog for", container.id);
			input.click();
		}
	});
}

// Fallback-Upload-Funktion mit File-Objekt
function uploadFileWithFile(file) {
	console.log("Uploading file directly:", file.name);

	var formData = new FormData();
	formData.append("file", file);

	document.getElementById("uploadProgressContainer").classList.remove("hidden");

	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/api/upload", true);

	xhr.upload.onprogress = function (event) {
		if (event.lengthComputable) {
			var percentComplete = (event.loaded / event.total) * 100;
			if (!xhr.upload.startTime) {
				xhr.upload.startTime = event.timeStamp;
			}
			var timeElapsed = (event.timeStamp - xhr.upload.startTime) / 1000;
			var speed = (event.loaded * 8) / (timeElapsed * 1024 * 1024);
			var estimatedTime =
				(event.total - event.loaded) / (event.loaded / timeElapsed);

			var timeDisplay;
			if (estimatedTime < 60) {
				timeDisplay = estimatedTime.toFixed(0) + " sec";
			} else if (estimatedTime < 3600) {
				timeDisplay = (estimatedTime / 60).toFixed(0) + " min";
			} else {
				timeDisplay = (estimatedTime / 3600).toFixed(2) + " hours";
			}

			document.getElementById("uploadProgress").style.width =
				percentComplete + "%";
			document.getElementById("uploadProgressPercentage").innerHTML =
				Math.round(percentComplete) + "%";
			document.getElementById("estTime").innerText = timeDisplay;
		}
	};

	xhr.onreadystatechange = function () {
		if (xhr.readyState == 4) {
			if (xhr.status == 201) {
				var response = JSON.parse(xhr.responseText);
				document.getElementById("fileUrlContainer").classList.remove("hidden");
				document.getElementById("fileurl").innerText = response.url;
				var url = response.url.replaceAll(" ", "%20");
				if (url.length > 70) {
					const shortUrl = url.slice(0, 58) + "..";
					document.getElementById("fileurl").innerHTML =
						"<a href='" + url + "' target='_blank'>" + shortUrl + "</a>";
				} else {
					document.getElementById("fileurl").innerHTML =
						"<a href='" + url + "' target='_blank'>" + url + "</a>";
				}
				document
					.getElementById("uploadProgressContainer")
					.classList.add("hidden");
			} else {
				raiseError(
					"Upload failed",
					"Failed to upload file. Status: " + xhr.status
				);
				document
					.getElementById("uploadProgressContainer")
					.classList.add("hidden");
			}
		}
	};

	xhr.send(formData);
}

// Debug-Funktion für Tests (optional)
function testDragAndDropSupport() {
	console.log("=== Drag & Drop Support Test ===");
	console.log("DataTransfer support:", "DataTransfer" in window);
	console.log("File API support:", "File" in window);
	console.log("FileList support:", "FileList" in window);
	console.log("FormData support:", "FormData" in window);

	// Test Container-Suche
	const containers = document.querySelectorAll(".container");
	console.log("Found containers:", containers.length);
	containers.forEach((container, index) => {
		console.log(`Container ${index + 1}:`, container.id, container);
	});

	// Test Input-Suche
	const fileUpload = document.getElementById("fileUpload");
	const convertFileInput = document.getElementById("convertFileInput");
	console.log("File upload input:", !!fileUpload);
	console.log("Convert file input:", !!convertFileInput);

	console.log("=== End Test ===");
}

function shortenUrl() {
	document.getElementById("shortUrlContainer").classList.add("hidden");
	document.getElementById("jsonResponseContainer").classList.add("hidden");
	var link = document.getElementById("urlInput").value;
	if (link == "") {
		return raiseError(
			"*insert nothing*",
			"Nothing is as short as it can get. Enter an URL to shorten it."
		);
	}
	if (!link.startsWith("http://") && !link.startsWith("https://")) {
		return raiseError("Huhttp?", "An URL without a protocol? Really?");
	}
	if (link.includes(" ")) {
		return raiseError(
			"Space? No space!",
			"An URL with a space? The space is really really big, but not in an URL."
		);
	}
	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/api/shorten", true);
	xhr.setRequestHeader("Content-Type", "application/json");
	xhr.onreadystatechange = function () {
		if (xhr.readyState == 4) {
			if (xhr.status == 201) {
				var response = JSON.parse(xhr.responseText);
				console.log(response);
				if (response.url) {
					document.getElementById("shortened").innerText = response.url;
					document
						.getElementById("shortUrlContainer")
						.classList.remove("hidden");
				} else {
					document.getElementById("jsonResponse").innerText = JSON.stringify(
						response,
						null,
						2
					);
					document
						.getElementById("jsonResponseContainer")
						.classList.remove("hidden");
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
		.catch((err) => {
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
	document.getElementById("");
	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/api/upload", true);

	xhr.upload.onprogress = function (event) {
		if (event.lengthComputable) {
			var percentComplete = (event.loaded / event.total) * 100;
			if (!xhr.upload.startTime) {
				xhr.upload.startTime = event.timeStamp;
			}
			var timeElapsed = (event.timeStamp - xhr.upload.startTime) / 1000; // time in seconds
			var speed = (event.loaded * 8) / (timeElapsed * 1024 * 1024); // speed in Mbit/s
			var estimatedTime =
				(event.total - event.loaded) / (event.loaded / timeElapsed); // estimated time in seconds

			var timeDisplay;
			if (estimatedTime < 60) {
				timeDisplay = estimatedTime.toFixed(0) + " sec";
			} else if (estimatedTime < 3600) {
				timeDisplay = (estimatedTime / 60).toFixed(0) + " min";
			} else {
				timeDisplay = (estimatedTime / 3600).toFixed(2) + " hours";
			}

			console.debug(
				"Speed: " +
					speed.toFixed(1) +
					" Mbit/s | Time elapsed: " +
					timeElapsed +
					" s | Estimated time: " +
					timeDisplay
			);
			document.getElementById("uploadProgress").style.width =
				percentComplete + "%";
			document.getElementById("uploadProgressPercentage").innerHTML =
				Math.round(percentComplete) + "%";
			document.getElementById("estTime").innerText = timeDisplay;
		}
	};

	xhr.onreadystatechange = function () {
		if (xhr.readyState == 4) {
			if (xhr.status == 201) {
				var response = JSON.parse(xhr.responseText);
				document.getElementById("fileUrlContainer").classList.remove("hidden");
				document.getElementById("fileurl").innerText = response.url;
				var url = response.url.replaceAll(" ", "%20");
				if (url.length > 70) {
					const shortUrl = url.slice(0, 58) + "..";
					document.getElementById("fileurl").innerHTML =
						"<a href='" + url + "' target='_blank'>" + shortUrl + "</a>";
				} else {
					document.getElementById("fileurl").innerHTML =
						"<a href='" + url + "' target='_blank'>" + url + "</a>";
				}
				document
					.getElementById("uploadProgressContainer")
					.classList.add("hidden");
			} else {
				raiseError(
					"We've lost your package!",
					"Failed to upload file. Status: " + xhr.status
				);
			}
		}
	};

	xhr.send(formData);
}

function convertFile(event) {
	event.preventDefault();

	var fileInput = document.getElementById("convertFileInput");
	var file = fileInput.files[0];
	var extensionSelect = document.getElementById("extensionSelect");
	var outputExt = extensionSelect.value;

	if (!file) {
		return raiseError("No file selected", "Please select a file to convert.");
	}
	if (!outputExt) {
		return raiseError("No format selected", "Please select a target format.");
	}

	var formData = new FormData();
	formData.append("output_ext", outputExt);
	formData.append("origin", window.origin);
	formData.append("file", file);

	// Fortschrittsanzeige anzeigen
	document
		.getElementById("convertProgressContainer")
		.classList.remove("hidden");
	document.getElementById("convertEtaContainer").classList.remove("hidden");
	document.getElementById("convertStatusContainer").classList.remove("hidden");
	document.getElementById("convertStatus").innerText = "Uploading file...";
	document.getElementById("convertEta").innerText = "";

	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/api/convert", true);

	xhr.upload.startTime = null;

	document.getElementById("convertProgress").classList.add("bg-blue-500");

	xhr.upload.onprogress = function (event) {
		if (event.lengthComputable) {
			var percentComplete = (event.loaded / event.total) * 100;
			document.getElementById("convertProgress").style.width =
				percentComplete + "%";
			document.getElementById("convertProgressPercentage").innerHTML =
				Math.round(percentComplete) + "%";

			if (!xhr.upload.startTime) {
				xhr.upload.startTime = event.timeStamp;
			}
			var timeElapsed = (event.timeStamp - xhr.upload.startTime) / 1000; // Sekunden
			var speed = (event.loaded * 8) / (timeElapsed * 1024 * 1024); // Mbit/s
			var estimatedTime =
				(event.total - event.loaded) / (event.loaded / timeElapsed); // Sekunden

			var timeDisplay;
			if (estimatedTime < 60) {
				timeDisplay = estimatedTime.toFixed(0) + " sec";
			} else if (estimatedTime < 3600) {
				timeDisplay = (estimatedTime / 60).toFixed(0) + " min";
			} else {
				timeDisplay = (estimatedTime / 3600).toFixed(2) + " hours";
			}
			document.getElementById("convertEta").innerText =
				"Estimated: " + timeDisplay;
		}
	};

	xhr.onreadystatechange = function () {
		if (xhr.readyState == 4) {
			if (xhr.status == 201) {
				var response = JSON.parse(xhr.responseText);
				// Starte Fortschrittsanzeige für Konvertierung
				sharePath = response.share_path;
				listenForConversionProgress(sharePath);
			} else {
				document.getElementById("convertStatus").innerText = "";
				document.getElementById("convertEta").innerText = "";
				document
					.getElementById("convertProgress")
					.classList.remove("bg-green-500");
				document.getElementById("convertProgress").classList.add("bg-blue-500");
				raiseError(
					"Conversion failed",
					"Failed to convert file. Status: " + xhr.status
				);
			}
		} else if (xhr.readyState == 2) {
			// Upload abgeschlossen, Konvertierung startet
			document.getElementById("convertStatus").innerText = "Converting...";
			document.getElementById("convertEta").innerText = "";
			document.getElementById("convertProgress").style.width = "0%";
			document.getElementById("convertProgressPercentage").innerHTML = "0%";
			document
				.getElementById("convertProgress")
				.classList.remove("bg-blue-500");
			document.getElementById("convertProgress").classList.add("bg-green-500");
		}
	};

	xhr.send(formData);

	// Starte SSE für Fortschritt - Variable für share_path
	var sharePath = null;
}

function listenForConversionProgress(sharePath) {
	var evtSource = new EventSource(
		"/api/convert_progress/" + encodeURIComponent(sharePath)
	);
	evtSource.onmessage = function (event) {
		var data = JSON.parse(event.data);
		if (data.debug) {
			console.debug("Conversion progress data:", data.debug);
		}
		if (data.percent !== undefined) {
			document.getElementById("convertProgress").style.width =
				data.percent + "%";
			document.getElementById("convertProgressPercentage").innerHTML =
				Math.round(data.percent) + "%";
		}
		if (data.eta !== undefined && data.eta !== null) {
			var eta = data.eta;
			var timeDisplay;
			if (eta < 60) {
				timeDisplay = eta.toFixed(0) + " sec";
			} else if (eta < 3600) {
				timeDisplay = (eta / 60).toFixed(0) + " min";
			} else {
				timeDisplay = (eta / 3600).toFixed(2) + " hours";
			}
			document.getElementById("convertEta").innerText =
				"Estimated: " + timeDisplay;
		}
		if (data.finished) {
			evtSource.close();
			document.getElementById("convertStatus").innerText =
				"Successfully converted!";
			// Fortschrittsbalken bleibt grün für abgeschlossene Konvertierung
			document
				.getElementById("convertProgress")
				.classList.remove("bg-blue-500");
			document.getElementById("convertProgress").classList.add("bg-green-500");
			document.getElementById("convertProgress").style.width = "100%";
			document.getElementById("convertProgressPercentage").innerHTML = "100%";
			// Link anzeigen
			console.log(data);
			if (data.share_path) {
				console.log("Share URL:", data.share_path);
				var new_share_url = window.origin + "/u/" + data.share_path;
				new_share_url = new_share_url.replaceAll(" ", "%20");
				document.getElementById("convertStatus").classList.add("hidden");
				document.getElementById("convertEta").classList.add("hidden");
				document
					.getElementById("convertProgressContainer")
					.classList.add("hidden");
				document.getElementById("convertResult").classList.remove("hidden");
				let displayUrl = new_share_url;
				if (new_share_url.length > 70) {
					displayUrl = new_share_url.slice(0, 58) + "..";
				}
				document.getElementById("convertedFileLink").innerHTML =
					"<a href='" +
					new_share_url +
					"' target='_blank'>" +
					displayUrl +
					"</a>";
			}
		}
	};
}

// Fallback-Funktion für direkten Upload mit File-Objekt
function uploadFileWithFile(file) {
	if (!file) {
		console.error("No file provided to uploadFileWithFile");
		return;
	}

	console.log("Using fallback upload method with file:", file.name);

	var formData = new FormData();
	formData.append("file", file);
	document.getElementById("uploadProgressContainer").classList.remove("hidden");

	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/api/upload", true);

	xhr.upload.onprogress = function (event) {
		if (event.lengthComputable) {
			var percentComplete = (event.loaded / event.total) * 100;
			if (!xhr.upload.startTime) {
				xhr.upload.startTime = event.timeStamp;
			}
			var timeElapsed = (event.timeStamp - xhr.upload.startTime) / 1000; // time in seconds
			var speed = (event.loaded * 8) / (timeElapsed * 1024 * 1024); // speed in Mbit/s
			var estimatedTime =
				(event.total - event.loaded) / (event.loaded / timeElapsed); // estimated time in seconds

			var timeDisplay;
			if (estimatedTime < 60) {
				timeDisplay = estimatedTime.toFixed(0) + " sec";
			} else if (estimatedTime < 3600) {
				timeDisplay = (estimatedTime / 60).toFixed(0) + " min";
			} else {
				timeDisplay = (estimatedTime / 3600).toFixed(2) + " hours";
			}

			console.debug(
				"Speed: " +
					speed.toFixed(1) +
					" Mbit/s | Time elapsed: " +
					timeElapsed +
					" s | Estimated time: " +
					timeDisplay
			);
			document.getElementById("uploadProgress").style.width =
				percentComplete + "%";
			document.getElementById("uploadProgressPercentage").innerHTML =
				Math.round(percentComplete) + "%";
			document.getElementById("estTime").innerText = timeDisplay;
		}
	};

	xhr.onreadystatechange = function () {
		if (xhr.readyState == 4) {
			if (xhr.status == 201) {
				var response = JSON.parse(xhr.responseText);
				document.getElementById("fileUrlContainer").classList.remove("hidden");
				document.getElementById("fileurl").innerText = response.url;
				var url = response.url.replaceAll(" ", "%20");
				if (url.length > 70) {
					const shortUrl = url.slice(0, 58) + "..";
					document.getElementById("fileurl").innerHTML =
						"<a href='" + url + "' target='_blank'>" + shortUrl + "</a>";
				} else {
					document.getElementById("fileurl").innerHTML =
						"<a href='" + url + "' target='_blank'>" + url + "</a>";
				}
				document
					.getElementById("uploadProgressContainer")
					.classList.add("hidden");
			} else {
				raiseError(
					"We've lost your package!",
					"Failed to upload file. Status: " + xhr.status
				);
			}
		}
	};

	xhr.send(formData);
}

// Format-Menü-Funktionen
function initializeFormatMenu() {
	console.log("Initializing format menu...");

	// Prüfe ob alle Elemente existieren
	const formatDisplay = document.querySelector(".format-display");
	const formatMenu = document.getElementById("formatMenu");
	const formatOptions = document.querySelectorAll(".format-option");

	if (!formatDisplay || !formatMenu || formatOptions.length === 0) {
		console.error("Format menu elements not found");
		return;
	}

	console.log("Found format menu elements:", {
		display: formatDisplay,
		menu: formatMenu,
		options: formatOptions.length,
	});

	// Event Listener für Format-Optionen
	formatOptions.forEach((option) => {
		option.addEventListener("click", function (e) {
			e.stopPropagation();
			console.log(
				"Format option clicked:",
				this.dataset.value,
				this.textContent
			);
			selectFormat(this.dataset.value, this.textContent);
		});
	});


	// Click außerhalb des Menüs schließt es
	document.addEventListener("click", function (e) {
		const formatSelector = document.querySelector(".format-selector");
		if (formatSelector && !formatSelector.contains(e.target)) {
			closeFormatMenu();
		}
	});

	console.log("Format menu initialization complete");
}

function toggleFormatMenu() {
	const menu = document.getElementById("formatMenu");
	const arrow = document.querySelector(".format-arrow");

	if (!menu || !arrow) {
		console.error("Format menu or arrow not found");
		return;
	}

	console.log(
		"Toggling format menu, current state:",
		menu.classList.contains("hidden")
	);

	if (menu.classList.contains("hidden")) {
		menu.classList.remove("hidden");
		arrow.classList.add("open");
		console.log("Format menu opened");
	} else {
		menu.classList.add("hidden");
		arrow.classList.remove("open");
		console.log("Format menu closed");
	}
}

function closeFormatMenu() {
	const menu = document.getElementById("formatMenu");
	const arrow = document.querySelector(".format-arrow");

	if (menu && !menu.classList.contains("hidden")) {
		menu.classList.add("hidden");
		console.log("Format menu closed");
	}

	if (arrow && arrow.classList.contains("open")) {
		arrow.classList.remove("open");
	}
}

function selectFormat(value, text) {
	console.log("Selecting format:", value, text);

	// Update Display
	const selectedFormat = document.getElementById("selectedFormat");
	if (selectedFormat) {
		selectedFormat.textContent = text;
		console.log("Updated display text to:", text);
	}

	// Update hidden input
	const extensionSelect = document.getElementById("extensionSelect");
	if (extensionSelect) {
		extensionSelect.value = value;
		console.log("Updated hidden input value to:", value);
	}

	// Update visual selection
	const formatOptions = document.querySelectorAll(".format-option");
	formatOptions.forEach((option) => {
		option.classList.remove("selected");
	});

	const selectedOption = document.querySelector(`[data-value="${value}"]`);
	if (selectedOption) {
		selectedOption.classList.add("selected");
		console.log("Updated visual selection");
	}

	// Close menu
	closeFormatMenu();
}
