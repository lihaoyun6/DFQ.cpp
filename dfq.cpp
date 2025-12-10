// dfq.cpp
// Single-file C++ implementation compatible with the provided JS code.
// Requires lodepng.h / lodepng.cpp in same directory.
//

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "lodepng/lodepng.h"
using namespace std;

// ------------------- PNG tEXt / iTXt extraction & insertion -------------------
struct TextChunk {
    string key;
    string value;
    string type;
};

// ------------------- Utilities -------------------
static inline int sgn_int(int x){ return (x>0)?1:((x<0)?-1:0); }
vector<uint8_t> readFileBytes(const string& path) {
    ifstream ifs(path, ios::binary);
    if (!ifs) return {};
    ifs.seekg(0, ios::end);
    size_t sz = (size_t)ifs.tellg();
    ifs.seekg(0);
    vector<uint8_t> buf(sz);
    if (sz) ifs.read((char*)buf.data(), sz);
    return buf;
}
bool writeFileBytes(const string& path, const vector<uint8_t>& data) {
    ofstream ofs(path, ios::binary);
    if (!ofs) return false;
    ofs.write((char*)data.data(), data.size());
    return true;
}

// ------------------- Password parsing (getPassWD JS equivalent) -------------------
array<int,3> parsePassword(const string &pw) {
    int step = 1, v = 0, h = 0;
    if (!pw.empty()) {
        try {
            string s0 = pw.size() >= 2 ? pw.substr(0,2) : pw;
            step = max(1, stoi(s0));
            v = (pw.size() >= 3 ? stoi(pw.substr(2,1)) : 0);
            h = (pw.size() >= 4 ? stoi(pw.substr(3,1)) : 0);
        } catch(...) {
            step = 1; v = 0; h = 0;
        }
    }
    return {step, v, h};
}

// ------------------- TEXT encryption (encryptTEXT / decryptTEXT JS equivalent) -------------------
// JS uses charCodeAt and String.fromCharCode with offsets key[i % key.length]
// We'll implement same per-character offset on C++ std::string bytes.
// Note: This mirrors the JS behavior for ASCII/UTF-8 bytes as used in the original project.
string encryptTEXT_cpp(const string &value, const vector<int>& key) {
    string out; out.reserve(value.size());
    for (size_t i=0;i<value.size();++i){
        unsigned char c = (unsigned char)value[i];
        int off = key[i % key.size()];
        unsigned char nc = (unsigned char)((int)c + off);
        out.push_back((char)nc);
    }
    return out;
}

string decryptTEXT_cpp(const string &value, const vector<int>& key) {
    string out; out.reserve(value.size());
    for (size_t i=0;i<value.size();++i){
        unsigned char c = (unsigned char)value[i];
        int off = key[i % key.size()];
        unsigned char nc = (unsigned char)((int)c - off);
        out.push_back((char)nc);
    }
    return out;
}

// ------------------- CRC calc (JS calculateCRC equivalent) -------------------
uint32_t calculateCRC_cpp(const vector<uint8_t>& data) {
    uint32_t crc = 0xffffffffu;
    for (size_t i=0;i<data.size();++i){
        crc ^= data[i];
        for (int j=0;j<8;++j){
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)(-(int)(crc & 1u)));
        }
    }
    return (crc ^ 0xffffffffu);
}

// Extract all tEXt and iTXt chunks (key,value). Mirrors JS extractTextChunks(file).  [oai_citation:8‡exif.js](sediment://file_00000000d46071fa9a4c70fefa3fa570)
vector<TextChunk> extractAllTextChunks_fromPNG(const vector<uint8_t>& pngBytes) {
    vector<TextChunk> chunks;
    const uint8_t pngSig[8] = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};
    if (pngBytes.size() < 8 || memcmp(pngBytes.data(), pngSig, 8) != 0) return chunks;
    size_t offset = 8;
    while (offset + 8 <= pngBytes.size()) {
        if (offset + 8 > pngBytes.size()) break;
        uint32_t length = (pngBytes[offset]<<24)|(pngBytes[offset+1]<<16)|(pngBytes[offset+2]<<8)|pngBytes[offset+3];
        if (offset + 12 + length > pngBytes.size()) break;
        string type(reinterpret_cast<const char*>(&pngBytes[offset+4]), 4);
        if (type == "tEXt" || type == "iTXt") {
            const uint8_t* data = pngBytes.data() + offset + 8;
            const uint8_t* end = data + length;
            // decode as raw bytes; JS used TextDecoder and then split by first NUL
            const uint8_t* nul = std::find(data, end, 0);
            if (nul == end) {
                string aggregate(reinterpret_cast<const char*>(data), length);
                // fallback: treat entire as value w/o key
                chunks.push_back({"", aggregate, type});
            } else {
                string key(reinterpret_cast<const char*>(data), nul - data);
                string value(reinterpret_cast<const char*>(nul + 1), end - (nul + 1));
                chunks.push_back({key, value, type});
            }
        }
        offset += 12 + length;
    }
    return chunks;
}

// Build tEXt chunks (encrypt/decrypt based on 'dec' flag) and insert before first IDAT, mirror writeTextChunksToNewBlob.  [oai_citation:9‡exif.js](sediment://file_00000000d46071fa9a4c70fefa3fa570)
vector<uint8_t> insertTextChunksBeforeIDAT(const vector<uint8_t>& pngBytes, const vector<TextChunk>& chunks, const vector<int>& key, bool dec) {
    // Build encrypted tEXt chunks
    vector<vector<uint8_t>> tchunks;
    for (auto &tc : chunks) {
        string processed = dec ? decryptTEXT_cpp(tc.value, key) : tc.value;
        // For iTXt we put same format as tEXt (keyword \0 value), JS limited handling.
        vector<uint8_t> data;
        data.insert(data.end(), tc.key.begin(), tc.key.end());
        data.push_back(0);
        data.insert(data.end(), processed.begin(), processed.end());
        // assemble chunk buffer: length(4) + type(4) + data + crc(4) will be appended later by assembler
        // we store just data+type here
        vector<uint8_t> chunk;
        // we will build complete chunk when assembling
        // store type and payload separately via simple struct - but here push structured bytes
        // We'll construct full chunk below.
        // save tEXt data only for now:
        // use wrapper: first 4 bytes will be length later
        tchunks.push_back(data);
    }

    // Parse original PNG into chunk list
    const uint8_t pngSig[8] = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};
    if (pngBytes.size() < 8 || memcmp(pngBytes.data(), pngSig, 8) != 0) throw runtime_error("Not a PNG");
    size_t offset = 8;
    vector<vector<uint8_t>> beforeChunks;
    vector<vector<uint8_t>> afterChunks;
    bool inserted = false;
    while (offset + 8 <= pngBytes.size()) {
        uint32_t length = (pngBytes[offset]<<24)|(pngBytes[offset+1]<<16)|(pngBytes[offset+2]<<8)|pngBytes[offset+3];
        if (offset + 12 + length > pngBytes.size()) break;
        string type(reinterpret_cast<const char*>(&pngBytes[offset+4]), 4);
        vector<uint8_t> chunk(pngBytes.begin()+offset, pngBytes.begin()+offset+12+length);
        if (!inserted && type == "IDAT") {
            // insert all tEXt chunks before this
            for (size_t i=0;i<tchunks.size();++i) {
                const vector<uint8_t>& data = tchunks[i];
                uint32_t L = (uint32_t)data.size();
                vector<uint8_t> full;
                full.push_back((L>>24)&0xFF); full.push_back((L>>16)&0xFF); full.push_back((L>>8)&0xFF); full.push_back((L)&0xFF);
                full.insert(full.end(), {'t','E','X','t'});
                full.insert(full.end(), data.begin(), data.end());
                // crc buffer
                vector<uint8_t> crcbuf;
                crcbuf.insert(crcbuf.end(), {'t','E','X','t'});
                crcbuf.insert(crcbuf.end(), data.begin(), data.end());
                uint32_t crc = calculateCRC_cpp(crcbuf);
                full.push_back((crc>>24)&0xFF); full.push_back((crc>>16)&0xFF); full.push_back((crc>>8)&0xFF); full.push_back((crc)&0xFF);
                beforeChunks.push_back(std::move(full));
            }
            inserted = true;
        }
        if (!inserted) beforeChunks.push_back(chunk); else afterChunks.push_back(chunk);
        offset += 12 + length;
    }
    // assemble
    vector<uint8_t> out;
    out.insert(out.end(), pngBytes.begin(), pngBytes.begin()+8);
    for (auto &c : beforeChunks) out.insert(out.end(), c.begin(), c.end());
    for (auto &c : afterChunks) out.insert(out.end(), c.begin(), c.end());
    return out;
}

// ------------------- Image padding / cropping (JS-equivalent) -------------------
vector<unsigned char> addPaddingToImageData_cpp(const vector<unsigned char>& originalData, int originalWidth, int originalHeight, int extraCols, int extraRows) {
    int newWidth = originalWidth + extraCols;
    int newHeight = originalHeight + extraRows;
    vector<unsigned char> newData((size_t)newWidth * newHeight * 4);
    for (int y=0;y<newHeight;++y){
        for (int x=0;x<newWidth;++x){
            int newIndex = 4 * (x + y * newWidth);
            if (y < originalHeight && x < originalWidth) {
                int oldIndex = 4 * (x + y * originalWidth);
                for (int k=0;k<4;++k) newData[newIndex+k] = originalData[oldIndex+k];
            } else if (y < originalHeight) {
                int lastColIndex = 4 * ((originalWidth - 1) + y * originalWidth);
                for (int k=0;k<4;++k) newData[newIndex+k] = originalData[lastColIndex+k];
            } else {
                int lastRowY = originalHeight - 1;
                int sourceX = min(x, originalWidth - 1);
                int lastRowIndex = 4 * (sourceX + lastRowY * originalWidth);
                for (int k=0;k<4;++k) newData[newIndex+k] = originalData[lastRowIndex+k];
            }
        }
    }
    return newData;
}

vector<unsigned char> cropImageData_cpp(const vector<unsigned char>& data, int originalWidth, int originalHeight, int removeCols, int removeRows) {
    int newWidth = originalWidth - removeCols;
    int newHeight = originalHeight - removeRows;
    vector<unsigned char> out((size_t)newWidth * newHeight * 4);
    for (int y=0;y<newHeight;++y){
        for (int x=0;x<newWidth;++x){
            int ni = (y * newWidth + x) * 4;
            int oi = (y * originalWidth + x) * 4;
            for (int k=0;k<4;++k) out[ni+k] = data[oi+k];
        }
    }
    return out;
}

static inline int js_sign(int v) {
    if (v > 0) return 1;
    if (v < 0) return -1;
    return 0; // JS has -0, but irrelevant on ints
}

void generate2d(int x, int y, int ax, int ay, int bx, int by,
    std::vector<std::pair<int,int>>& coords)
{
    int w = std::abs(ax + ay);
    int h = std::abs(bx + by);
    
    int dax = js_sign(ax), day = js_sign(ay);
    int dbx = js_sign(bx), dby = js_sign(by);
    
    if (h == 1) {
        for (int i=0;i<w;i++) {
            coords.emplace_back(x, y);
            x += dax;
            y += day;
        }
        return;
    }
    
    if (w == 1) {
        for (int i=0;i<h;i++) {
            coords.emplace_back(x, y);
            x += dbx;
            y += dby;
        }
        return;
    }
    
    int ax2 = (int)std::floor(ax / 2.0);
    int ay2 = (int)std::floor(ay / 2.0);
    int bx2 = (int)std::floor(bx / 2.0);
    int by2 = (int)std::floor(by / 2.0);
    
    int w2 = std::abs(ax2 + ay2);
    int h2 = std::abs(bx2 + by2);
    
    if (2*w > 3*h) {
        if ((w2 % 2) && (w > 2)) {
            ax2 += dax;
            ay2 += day;
        }
        
        generate2d(x, y, ax2, ay2, bx, by, coords);
        generate2d(x + ax2, y + ay2, ax - ax2, ay - ay2, bx, by, coords);
    }
    else {
        if ((h2 % 2) && (h > 2)) {
            bx2 += dbx;
            by2 += dby;
        }
        
        generate2d(x, y, bx2, by2, ax2, ay2, coords);
        generate2d(x + bx2, y + by2, ax, ay, bx - bx2, by - by2, coords);
        generate2d(
            x + (ax - dax) + (bx2 - dbx),
            y + (ay - day) + (by2 - dby),
            -bx2, -by2,
            -(ax - ax2), -(ay - ay2),
            coords
        );
    }
}

std::vector<std::pair<int,int>> gilbert2d(int width, int height) {
    std::vector<std::pair<int,int>> c;
    c.reserve(width * height);
    
    if (width >= height)
        generate2d(0,0, width,0, 0,height, c);
    else
        generate2d(0,0, 0,height, width,0, c);
    
    return c;
}

// ------------------- Build single-step permutation and perm^k -------------------
vector<int> build_single_step_perm(int width, int height) {
    int N = width * height;
    vector<int> perm(N, -1);
    auto coords = gilbert2d(width, height);
    int offset = (int)lround(((sqrt(5.0) - 1.0) / 2.0) * (double)N);
    for (int i=0;i<N;++i) {
        int ox = coords[i].first, oy = coords[i].second;
        int nx = coords[(i + offset) % N].first, ny = coords[(i + offset) % N].second;
        int oldIndex = ox + oy * width;
        int newIndex = nx + ny * width;
        perm[oldIndex] = newIndex;
    }
    for (int i=0;i<N;++i) if (perm[i] < 0) perm[i] = i;
    return perm;
}
vector<int> compose_perm(const vector<int>& a, const vector<int>& b) {
    int n = (int)a.size();
    vector<int> r(n);
    for (int i=0;i<n;++i) r[i] = a[b[i]];
    return r;
}
vector<int> perm_power(const vector<int>& perm, int k) {
    int n = (int)perm.size();
    vector<int> res(n);
    for (int i=0;i<n;++i) res[i] = i; // identity
    if (k <= 0) return res;
    vector<int> base = perm;
    int kk = k;
    while (kk > 0) {
        if (kk & 1) res = compose_perm(base, res);
        base = compose_perm(base, base);
        kk >>= 1;
    }
    return res;
}

// ------------------- Parallel apply (encrypt: dst[perm_k[old]] = src[old]) -------------------
void apply_perm_once_parallel_copy(const unsigned char* src, unsigned char* dst, int N, const vector<int>& perm, int num_threads = 0) {
    if (num_threads <= 0) num_threads = max(1u, std::thread::hardware_concurrency());
    vector<thread> threads; threads.reserve(num_threads);
    int chunk = (N + num_threads - 1) / num_threads;
    for (int t=0;t<num_threads;++t) {
        int s = t * chunk;
        int e = min(N, s + chunk);
        if (s >= e) break;
        threads.emplace_back([=,&perm]() {
            const unsigned char* S = src;
            unsigned char* D = dst;
            for (int i=s;i<e;++i) {
                int to = perm[i];
                int si = i*4; int di = to*4;
                D[di    ] = S[si    ];
                D[di + 1] = S[si + 1];
                D[di + 2] = S[si + 2];
                D[di + 3] = S[si + 3];
            }
        });
    }
    for (auto &th : threads) th.join();
}

// ------------------- Optimized encrypt/decrypt image data (perm^step + single copy) -------------------
vector<unsigned char> encryptImageData_optimized(const vector<unsigned char>& rgba, int width, int height, int step, int v, int hpad) {
    int N = width * height;
    vector<int> perm = build_single_step_perm(width, height);
    vector<int> perm_k = perm_power(perm, step);
    vector<unsigned char> dst((size_t)N * 4);
    apply_perm_once_parallel_copy(rgba.data(), dst.data(), N, perm_k);
    vector<unsigned char> finalData = addPaddingToImageData_cpp(dst, width, height, v, hpad);
    return finalData;
}
vector<unsigned char> decryptImageData_optimized(const vector<unsigned char>& rgba_cropped, int width, int height, int step) {
    // width,height are original (cropped) dims
    int N = width * height;
    vector<int> perm = build_single_step_perm(width, height);
    vector<int> perm_k = perm_power(perm, step);
    // To reconstruct original: original[i] = encrypted[perm_k[i]]
    vector<unsigned char> dst((size_t)N * 4);
    int num_threads = max(1u, std::thread::hardware_concurrency());
    vector<thread> ths; ths.reserve(num_threads);
    int chunk = (N + num_threads - 1) / num_threads;
    for (int t=0;t<num_threads;++t) {
        int s = t*chunk;
        int e = min(N, s+chunk);
        if (s >= e) break;
        ths.emplace_back([=,&perm_k,&rgba_cropped,&dst]() {
            for (int i=s;i<e;++i) {
                int srcIdx = perm_k[i];
                int si = srcIdx*4; int di = i*4;
                dst[di    ] = rgba_cropped[si    ];
                dst[di + 1] = rgba_cropped[si + 1];
                dst[di + 2] = rgba_cropped[si + 2];
                dst[di + 3] = rgba_cropped[si + 3];
            }
        });
    }
    for (auto &t : ths) t.join();
    return dst;
}

// ------------------- Top-level encrypt / decrypt flows -------------------
int runEncrypt(const string& inPath, const string& outPath, const string& password) {
    // 1. read original PNG bytes and extract text chunks
    vector<uint8_t> origBytes = readFileBytes(inPath);
    if (origBytes.empty()) { cerr<<"cannot read input\n"; return 1; }
    // attempt decode using lodepng to get rgba
    vector<unsigned char> rgba; unsigned w,h;
    unsigned err = lodepng::decode(rgba, w, h, origBytes);
    if (err) { cerr<<"decode error: "<<lodepng_error_text(err)<<"\n"; return 2; }
    auto pw = parsePassword(password);
    int step = pw[0], v = pw[1], hpad = pw[2];
    vector<int> keyVec = {pw[0], pw[1], pw[2]};

    // extract all text chunks from original PNG and encrypt their values
    vector<TextChunk> origTextChunks = extractAllTextChunks_fromPNG(origBytes);
    vector<TextChunk> encryptedTextChunks;
    encryptedTextChunks.reserve(origTextChunks.size());
    for (auto &tc : origTextChunks) {
        string enc = encryptTEXT_cpp(tc.value, keyVec);
        encryptedTextChunks.push_back({tc.key, enc, tc.type});
    }

    // encrypt pixels (original width/height)
    vector<unsigned char> encRGBA = encryptImageData_optimized(rgba, (int)w, (int)h, step, v, hpad);

    unsigned newW = w + v; unsigned newH = h + hpad;
    vector<uint8_t> pngOut;
    err = lodepng::encode(pngOut, encRGBA, newW, newH);
    if (err) { cerr<<"encode error: "<<lodepng_error_text(err)<<"\n"; return 3; }

    // insert encrypted tEXt chunks before first IDAT (mirrors JS writeTextChunksToNewBlob)
    vector<uint8_t> finalPng = insertTextChunksBeforeIDAT(pngOut, encryptedTextChunks, keyVec, false);

    if (!writeFileBytes(outPath, finalPng)) { cerr<<"write out failed\n"; return 4; }
    cout<<"Encrypted saved to "<<outPath<<"\n";
    return 0;
}

int runDecrypt(const string& inPath, const string& outPath, const string& password) {
    // 1. read PNG and decode
    vector<uint8_t> pngBytes = readFileBytes(inPath);
    if (pngBytes.empty()) { cerr<<"cannot read input\n"; return 1; }
    vector<unsigned char> rgba; unsigned w,h;
    unsigned err = lodepng::decode(rgba, w, h, pngBytes);
    if (err) { cerr<<"decode error: "<<lodepng_error_text(err)<<"\n"; return 2; }
    auto pw = parsePassword(password);
    int step = pw[0], v = pw[1], hpad = pw[2];
    vector<int> keyVec = {pw[0], pw[1], pw[2]};

    // extract encrypted tEXt chunks and decrypt their values
    vector<TextChunk> encTextChunks = extractAllTextChunks_fromPNG(pngBytes);
    vector<TextChunk> decTextChunks; decTextChunks.reserve(encTextChunks.size());
    for (auto &tc : encTextChunks) {
        string dec = decryptTEXT_cpp(tc.value, keyVec);
        decTextChunks.push_back({tc.key, dec, tc.type});
    }

    // crop padding (JS decrypt expects imageData width= w-v , height = h-hpad)
    if ((int)w - v <= 0 || (int)h - hpad <= 0) { cerr<<"invalid padding size\n"; return 3; }
    vector<unsigned char> cropped = cropImageData_cpp(rgba, (int)w, (int)h, v, hpad);

    // decrypt pixels
    vector<unsigned char> decoded = decryptImageData_optimized(cropped, (int)w - v, (int)h - hpad, step);

    // re-encode original image
    vector<uint8_t> outPng;
    err = lodepng::encode(outPng, decoded, (unsigned)(w - v), (unsigned)(h - hpad));
    if (err) { cerr<<"encode error: "<<lodepng_error_text(err)<<"\n"; return 4; }

    // insert decrypted tEXt back (optional; mirrors JS behavior that writes dec when dec flag true)
    vector<uint8_t> finalPng = insertTextChunksBeforeIDAT(outPng, decTextChunks, keyVec, true);

    if (!writeFileBytes(outPath, finalPng)) { cerr<<"write out failed\n"; return 5; }
    cout<<"Decrypted saved to "<<outPath<<"\n";
    return 0;
}

// ------------------- main -------------------
int main(int argc, char** argv) {
    ios::sync_with_stdio(false);
    if (argc < 4) {
        cerr<<"Usage:\n  "<<argv[0]<<" encrypt in.png out.png [password]\n  "<<argv[0]<<" decrypt in.png out.png [password]\n";
        return 1;
    }
    string mode = argv[1];
    if (mode == "encrypt") {
        string in = argv[2], out = argv[3];
        string pw = (argc >= 5 ? argv[4] : string());
        return runEncrypt(in,out,pw);
    } else if (mode == "decrypt") {
        string in = argv[2], out = argv[3];
        string pw = (argc >= 5 ? argv[4] : string());
        return runDecrypt(in,out,pw);
    } else {
        cerr<<"unknown mode\n";
        return 1;
    }
}