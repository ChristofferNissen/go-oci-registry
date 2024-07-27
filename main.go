package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/distribution/distribution/uuid"
	_ "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-manifests
	nameRegex   string = "^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$"
	refRegex    string = "^[a-zA-Z0-9_][a-zA-Z0-9._-]{1,127}$"
	digestRegex string = "^sha256:([a-f0-9]{64})$"
)

type ErrorResponse struct {
	Errors []ErrorDetail `json:"errors"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

type TagList struct {
	Name    string   `json:"name"`
	TagList []string `json:"tags"`
}

func main() {
	fmt.Println("Starting...")
	logFlags := log.LstdFlags | log.LUTC
	if e := os.Getenv("DEBUG"); e != "" {
		logFlags = logFlags | log.Lshortfile
	}
	log.SetFlags(logFlags)
	rootDir := setupStorage()
	log.Printf("Storage: %s", rootDir)
	http.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if e := os.Getenv("DEBUG"); e != "" {
			printInfo(r)
		}
		// end-1
		if r.Method == "GET" && r.RequestURI == "/v2/" {
			w.WriteHeader(200)
			return
		}

		name, err := parseName(r.RequestURI)
		if err != nil {
			writeServerError(err, w)
			return
		}
		if !matches(nameRegex, name) {
			writeOCIError("NAME_INVALID", "invalid repository name", w, 400)
			return
		}
		endpoint := strings.TrimPrefix(r.RequestURI, strings.Join([]string{"/v2/", name}, ""))
		if e := os.Getenv("DEBUG"); e != "" {
			log.Printf("Endpoint: %s", endpoint)
		}

		// end-2
		if (r.Method == "HEAD" || r.Method == "GET") && strings.Contains(endpoint, "/blobs/sha256:") {
			parts := strings.Split(endpoint, "/")
			requestDigest := parts[len(parts)-1]
			if !matches(digestRegex, requestDigest) {
				writeOCIError("BLOB_UNKNOWN", "blob unknown to registry", w, 404)
				return
			}
			blobPath := path.Join(rootDir, name, "_blobs", requestDigest)
			b, err := fileExists(blobPath)
			var status int
			if err != nil {
				writeServerError(err, w)
				return
			}
			if b {
				w.Header().Set("Docker-Content-Digest", requestDigest)
				status = 200

				if r.Method == "GET" {
					content, e := readFile(blobPath)
					if e != nil {
						writeServerError(e, w)
						return
					}
					_, err := content.WriteTo(w)
					if err != nil {
						writeServerError(err, w)
						return
					}
				}
			} else {
				status = 404
			}
			w.WriteHeader(status)
		}
		// end-3
		if (r.Method == "HEAD" || r.Method == "GET") && strings.Contains(endpoint, "/manifests/") {
			parts := strings.Split(endpoint, "/")
			lastPart := parts[len(parts)-1]
			isRef := matches(refRegex, lastPart)
			isDigest := matches(digestRegex, lastPart)

			if !(isRef || isDigest) {
				writeOCIError("MANIFEST_INVALID", "manifest invalid", w, 404)
				return
			}
			manifestPath := path.Join(rootDir, name)
			if isRef {
				manifestPath = path.Join(manifestPath, lastPart, "manifest.json")
			} else {
				foundPath, err := findManifest(rootDir, name, lastPart)
				if err != nil {
					w.WriteHeader(404)
					return
				}
				if foundPath == "" {
					writeOCIError("MANIFEST_UNKNOWN", "manifest unknown to registry", w, 404)
					return
				}
				manifestPath = foundPath
			}
			log.Printf("Manifest path: %s", manifestPath)
			b, err := fileExists(manifestPath)
			if err != nil {
				writeServerError(err, w)
				return
			}
			if b {
				if r.Method == "GET" {
					content, e := readFile(manifestPath)
					if e != nil {
						writeServerError(e, w)
						return
					}
					_, err := content.WriteTo(w)
					if err != nil {
						writeServerError(err, w)
						return
					}
				}
				w.WriteHeader(200)
			} else {
				w.WriteHeader(404)
			}
		}
		// end-4a
		if r.Method == "POST" && strings.HasSuffix(endpoint, "/blobs/uploads/") {
			id := uuid.Generate().String()
			w.Header().Set("Location", r.RequestURI+id)
			w.WriteHeader(202)
		}
		// end-4b
		if r.Method == "POST" && strings.Contains(endpoint, "/blobs/uploads/") && r.FormValue("mount") == "" {
			digest := r.FormValue("digest")
			if digest == "" {
				http.Error(w, "Digest missing", 400)
				return
			}
			destFile := path.Join(rootDir, name, "_blobs", digest)
			writeBodyToFileWithLocation(destFile, w, r, name, digest)
			return
		}
		// end-5
		if r.Method == "PATCH" && strings.Contains(endpoint, "/blobs/uploads/") {
			parts := strings.Split(endpoint, "/")
			location := parts[len(parts)-1]
			w.Header().Set("Location", r.RequestURI)

			l := r.Header.Get("Content-Length")
			i, err := strconv.Atoi(l)
			if err != nil {
				writeServerError(err, w)
				return
			}

			cr := r.Header.Get("Content-Range")

			destFile := path.Join(rootDir, name, "_blobs", location)
			if cr == "" {
				// first chunck
				createFile(destFile, i, w, r)
			} else {
				// subsequent chunks
				elem := strings.Split(cr, "-")
				start, _ := elem[0], elem[1]
				start64, err := strconv.ParseInt(start, 10, 64)
				if err != nil {
					writeServerError(err, w)
					return
				}

				s, err := strconv.Atoi(start)
				if err != nil {
					writeServerError(err, w)
					return
				}

				f, err := os.OpenFile(destFile, os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					writeServerError(err, w)
					return
				}
				defer f.Close()

				buf := make([]byte, s)
				n, err := f.Read(buf)
				if err != nil {
					w.WriteHeader(416)
					return
				}

				if n != s {
					w.WriteHeader(416)
					return
				}

				// chunk already in registry?
				buf = make([]byte, i)
				n, err = f.ReadAt(buf, start64)
				if err == nil && n == i {
					// could read current chunk from file, so return 416
					w.WriteHeader(416)
					return
				}

				buf = make([]byte, i)
				r.Body.Read(buf)
				// _, err = r.Body.Read(buf)
				// log.Println(n)
				// if err != nil {
				// 	writeServerError(err, w)
				// 	return
				// }

				_, err = f.WriteAt(buf, start64)
				if err != nil {
					writeServerError(err, w)
					return
				}

				w.Header().Set("Range", fmt.Sprintf("%d-%d", 0, i-1))

			}

			w.WriteHeader(202)
		}
		// end-6
		if r.Method == "PUT" && strings.Contains(endpoint, "/blobs/uploads/") {

			parts := strings.Split(endpoint, "/")
			parts2 := strings.Split(parts[len(parts)-1], "?")
			location := parts2[0]

			cl := w.Header().Get("Content-Length")
			cr := w.Header().Get("Content-Range")
			log.Println(cr)
			log.Println(cl)

			// chunked upload or not
			b, _ := fileExists(path.Join(rootDir, name, "_blobs", location))
			log.Println(b)
			if b {
				// Add flow for when finishing chunk upload.
				// write body to location if any
				// Need to move location to digest
				// Send response back to user with url for fetching finished upload
				buf := make([]byte, 1)
				n, _ := r.Body.Read(buf)
				log.Println(n)
				log.Println(string(buf))

				digest := r.FormValue("digest")
				os.Rename(path.Join(rootDir, name, "_blobs", location), path.Join(rootDir, name, "_blobs", digest))

				w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
				w.WriteHeader(201)

				return
			} else {

				err := os.MkdirAll(path.Join(rootDir, name, "_blobs"), 0755)
				if err != nil {
					writeServerError(err, w)
					return
				}
				digest := r.FormValue("digest")
				log.Printf("Digest: %s", digest)
				destFile := path.Join(rootDir, name, "_blobs", digest)
				writeBodyToFileWithLocation(destFile, w, r, name, digest)
			}
		}
		// end-7
		if r.Method == "PUT" && strings.Contains(endpoint, "/manifests/") {
			parts := strings.Split(endpoint, "/manifests/")
			requestRef := parts[len(parts)-1]
			// if !matches(refRegex, requestRef) {
			// 	writeOCIError("MANIFEST_INVALID", "manifest invalid", w, 400)
			// 	return
			// }
			err := os.MkdirAll(path.Join(rootDir, name, requestRef), 0755)
			if err != nil {
				writeServerError(err, w)
				return
			}
			destFile := path.Join(rootDir, name, requestRef, "manifest.json")
			writeBodyToFile(destFile, w, r)

			f, err := os.Open(destFile)
			if err != nil {
				writeServerError(err, w)
				return
			}
			var buf bytes.Buffer
			_, err = buf.ReadFrom(f)
			if err != nil {
				writeServerError(err, w)
				return
			}
			digest := getDigest(buf.Bytes())
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, digest))

			w.WriteHeader(201)
		}
		// end-8a
		if r.Method == "GET" && strings.HasSuffix(endpoint, "/tags/list") && r.FormValue("last") == "" {
			if _, err := os.ReadDir(path.Join(rootDir, name)); err != nil {
				writeOCIError("NAME_UNKNOWN", "repository name not known to registry", w, 404)
				return
			}
			tags, err := getTags(path.Join(rootDir, name))
			if err != nil {
				writeServerError(err, w)
				return
			}
			tl := TagList{
				Name:    name,
				TagList: tags,
			}
			jb, jE := json.Marshal(tl)
			if jE != nil {
				writeServerError(jE, w)
				return
			}
			_, wE := w.Write(jb)
			if wE != nil {
				writeServerError(wE, w)
				return
			}
			return
		}
		// end-8b
		if r.Method == "GET" && strings.HasSuffix(endpoint, "/tags/list") {
			n := r.FormValue("n")
			last := r.FormValue("last")

			if _, err := os.ReadDir(path.Join(rootDir, name)); err != nil {
				writeOCIError("NAME_UNKNOWN", "repository name not known to registry", w, 404)
				return
			}
			tags, err := getTags(path.Join(rootDir, name))
			if err != nil {
				writeServerError(err, w)
				return
			}

			slices.Sort(tags)

			if last != "" {
				i := slices.Index(tags, last)
				tags = tags[i:]
			}

			if n != "" {
				// string to int
				i, err := strconv.Atoi(n)
				if err != nil {
					// ... handle error
					panic(err)
				}

				tags = tags[:i]
			}

			tl := TagList{
				Name:    name,
				TagList: tags,
			}
			jb, jE := json.Marshal(tl)
			if jE != nil {
				writeServerError(jE, w)
				return
			}
			_, wE := w.Write(jb)
			if wE != nil {
				writeServerError(wE, w)
				return
			}
			return
		}
		// end-9 (delete manifest)
		if r.Method == "DELETE" && strings.Contains(endpoint, "/manifests/") {

			parts := strings.Split(endpoint, "/")
			lastPart := parts[len(parts)-1]
			isRef := matches(refRegex, lastPart)
			isDigest := matches(digestRegex, lastPart)

			if !(isRef || isDigest) {
				writeOCIError("MANIFEST_INVALID", "manifest invalid", w, 404)
				return
			}

			manifestPath := path.Join(rootDir, name, lastPart)
			err := os.RemoveAll(manifestPath)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(202)
			return

		}
		// end-10 (delete blob)
		if r.Method == "DELETE" && strings.Contains(endpoint, "/blobs/") {
			parts := strings.Split(endpoint, "/")
			requestDigest := parts[len(parts)-1]
			if !matches(digestRegex, requestDigest) {
				writeOCIError("BLOB_UNKNOWN", "blob unknown to registry", w, 404)
				return
			}
			blobPath := path.Join(rootDir, name, "_blobs", requestDigest)
			b, err := fileExists(blobPath)
			if err != nil {
				writeServerError(err, w)
				return
			}
			if b {
				err := os.RemoveAll(blobPath)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				w.WriteHeader(202)
				return
			} else {
				w.WriteHeader(404)
				return
			}
		}
		// end-11
		if r.Method == "POST" && strings.Contains(endpoint, "/blobs/uploads/") {

			m := r.FormValue("mount")
			f := r.FormValue("from")

			// name: is the namespace to which the blob will be mounted
			// f: is the namespace from which the blob should be mounted

			// check if blob exists

			old := path.Join(rootDir, f, "_blobs", m)

			b, err := fileExists(old)
			if err != nil {
				writeServerError(err, w)
				return
			}
			if !b || f == "" {
				// unable to mount
				id := uuid.Generate().String()
				p := fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, id)
				w.Header().Set("Location", p)
				w.WriteHeader(202)
				return
			}

			new := path.Join(rootDir, name, "_blobs", m)
			os.MkdirAll(path.Join(rootDir, name, "_blobs"), fs.ModePerm)
			err = os.Link(old, new)
			if err != nil {
				log.Println(err.Error())
				writeServerError(err, w)
				return
			}

			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, m))
			w.WriteHeader(201)
			return
		}
		// end-12a (referres)
		if r.Method == "GET" && strings.Contains(endpoint, "/referrers/") && r.FormValue("artifactType") == "" {

			// d := r.FormValue("digest")

			// isRef := matches(refRegex, d)
			// isDigest := matches(digestRegex, d)

			// if !(isRef || isDigest) {
			// 	writeOCIError("MANIFEST_INVALID", "manifest invalid", w, 400)
			// 	return
			// }

			// w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")

			w.WriteHeader(404)
			return
		}
		// end-12b (referres)
		if r.Method == "GET" && strings.Contains(endpoint, "/referrers/") && r.FormValue("artifactType") == "" {

			// d := r.FormValue("digest")
			// // at := r.FormValue("artifactType")

			// isRef := matches(refRegex, d)
			// isDigest := matches(digestRegex, d)

			// if !(isRef || isDigest) {
			// 	writeOCIError("MANIFEST_INVALID", "manifest invalid", w, 404)
			// 	return
			// }

			w.WriteHeader(404)
			return
		}
		// end-13
		if r.Method == "GET" && strings.Contains(endpoint, "/blobs/uploads/") {
			parts := strings.Split(endpoint, "/")
			location := parts[len(parts)-1]

			// determine length of current file
			destFile := path.Join(rootDir, name, "_blobs", location)
			fileInfo, err := os.Stat(destFile)
			if err != nil {
				writeServerError(err, w)
				return
			}
			l := fileInfo.Size() - 1

			w.Header().Set("Location", r.RequestURI)
			w.Header().Set("Range", fmt.Sprintf("%d-%d", 0, l))
			w.WriteHeader(204)
			return
		}

	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getTags(path string) ([]string, error) {
	tags := make([]string, 0)
	files, err := os.ReadDir(path)
	if err != nil {
		return tags, err
	}
	for _, de := range files {
		if de.Name() == "_blobs" {
			continue
		}
		tags = append(tags, de.Name())
	}
	return tags, nil
}

func writeServerError(err error, w http.ResponseWriter) {
	es := fmt.Sprintf("Unexpected error encountered: %s", err.Error())
	http.Error(w, es, 500)
}

func writeBodyToFileWithLocation(destFile string, w http.ResponseWriter, r *http.Request, name string, digest string) {
	writeBodyToFile(destFile, w, r)
	if !validateBlob(destFile, r.ContentLength, digest) {
		http.Error(w, "blob did not match length or digest", 400)
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
	w.WriteHeader(201)
}

func writeBodyToFile(destFile string, w http.ResponseWriter, r *http.Request) {
	var f *os.File
	if _, statE := os.Stat(destFile); os.IsNotExist(statE) {
		innerF, err := os.OpenFile(destFile, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			writeServerError(err, w)
			return
		}
		f = innerF
	} else {
		innerF, err := os.OpenFile(destFile, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			writeServerError(err, w)
			return
		}
		err = os.Truncate(destFile, 0)
		if err != nil {
			writeServerError(err, w)
			return
		}
		f = innerF
	}
	total := r.ContentLength
	buf := make([]byte, 1024)
	for {
		n, err := r.Body.Read(buf)
		_, err2 := f.Write(buf[0:n])
		if err2 != nil {
			log.Printf("Failed to write buffer to file: %s", err2)
		}
		if err == io.EOF {
			break
		}
		total = total - int64(n)
		if total > 0 {
			for i := 0; i < 1024; i++ {
				buf[i] = 0
			}
		}
	}
}

func writeBodyChunkToFile(destFile string, start, end int64, len int, w http.ResponseWriter, r *http.Request) {

	f, err := os.OpenFile(destFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		writeServerError(err, w)
		return
	}

	// b, _ := io.ReadAll(f)

	buf := make([]byte, len)
	r.Body.Read(buf)
	// log.Println(n)
	// if err != nil {
	// 	writeServerError(err, w)
	// 	return
	// }

	_, err = f.WriteAt(buf, start)
	if err != nil {
		writeServerError(err, w)
		return
	}
}

func createFile(destFile string, contentLength int, w http.ResponseWriter, r *http.Request) {
	_, err := os.OpenFile(destFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		writeServerError(err, w)
		return
	}

	err = os.Truncate(destFile, 0)
	if err != nil {
		writeServerError(err, w)
		return
	}
	// buf := make([]byte, contentLength)
	// _, err = f.Write(buf)
	// if err != nil {
	// 	writeServerError(err, w)
	// 	return
	// }
}

func readFile(path string) (bytes.Buffer, error) {
	var b bytes.Buffer
	f, err := os.Open(path)
	if err != nil {
		return b, err
	}
	_, readE := b.ReadFrom(f)
	if readE != nil {
		return bytes.Buffer{}, readE
	}
	return b, nil
}

func setupStorage() string {
	dir, wdErr := os.Getwd()
	if wdErr != nil {
		log.Printf(wdErr.Error())
	}
	dir = path.Join(dir, "data")
	_, readErr := os.ReadDir(dir)
	if readErr != nil {
		if errors.Is(readErr, fs.ErrNotExist) {
			mkErr := os.MkdirAll(dir, 0755)
			if mkErr != nil {
				log.Printf(mkErr.Error())
			}
		} else {
			log.Printf(readErr.Error())
		}
	}
	return dir
}

func printInfo(r *http.Request) {
	client := r.Host
	method := r.Method
	uri := r.RequestURI
	conType := r.Header.Get("Content-Type")
	accept := r.Header.Get("Accept")

	log.Printf("Request details:")
	log.Printf("\tHost: %s", client)
	log.Printf("\tMethod: %s", method)
	log.Printf("\tURI: %s", uri)
	if conType != "" {
		log.Printf("\tContent-Type: %s", conType)
	}
	if accept != "" {
		log.Printf("\tAccept: %s", accept)
	}
}

func writeOCIError(code string, message string, w http.ResponseWriter, statusCode int) {
	e := ErrorResponse{
		Errors: []ErrorDetail{{
			Code:    code,
			Message: message,
			Detail:  "{}",
		}},
	}
	out, err := json.Marshal(e)
	if err != nil {
		log.Printf("Unable to marshall error response: %s", err.Error())
		http.Error(w, err.Error(), 500)
	}
	http.Error(w, string(out[:]), statusCode)
}

func parseName(url string) (string, error) {
	s := strings.TrimPrefix(url, "/v2/")
	paths := strings.Count(s, "/")
	var name = ""
	if paths <= 1 {
		return "", errors.New(fmt.Sprintf("URL does not match any valid OCI endpoint: %s", url))
	}
	if paths == 2 {
		name = strings.Split(s, "/")[0]
	} else {
		parts := make([]string, 0)
		for _, p := range strings.Split(s, "/") {
			if p == "blobs" || p == "manifests" || p == "tags" || p == "referrers" {
				break
			}
			parts = append(parts, p)
		}
		name = strings.Join(parts, "/")
	}
	return name, nil
}

func matches(pattern string, name string) bool {
	matched, err := regexp.MatchString(pattern, name)
	if err != nil {
		log.Printf("Error while parsing regex: %s", err.Error())
	}
	return matched
}

func fileExists(path string) (bool, error) {
	_, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		} else {
			return false, errors.New(fmt.Sprintf("Unexpected error while checking existence of %s: %s", path, err))
		}
	}
	return true, nil
}

func findManifest(rootDir string, name string, digest string) (string, error) {
	files, err := os.ReadDir(path.Join(rootDir, name))
	if err != nil {
		return "", err
	}
	for _, de := range files {
		if de.Name() == "_blobs" {
			continue
		}
		if de.IsDir() {
			manifestPath := path.Join(rootDir, name, de.Name(), "manifest.json")
			f, fE := os.Open(manifestPath)
			if fE != nil {
				return "", fE
			}
			var buf bytes.Buffer
			_, err := buf.ReadFrom(f)
			if err != nil {
				return "", err
			}
			thisDigest := getDigest(buf.Bytes())
			if thisDigest == digest {
				return manifestPath, nil
			}
		}
	}
	return "", nil
}

func getDigest(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", h)
}

func validateBlob(filePath string, fileLen int64, digest string) bool {
	b, e := readFile(filePath)
	if e != nil {
		log.Print(e)
		return false
	}
	return getDigest(b.Bytes()) == digest
}
