# DFQ.cpp
"大番茄图片混淆"的C++实现  

# 预览
![Image](https://github.com/user-attachments/assets/0fa9d3ed-00c4-4c70-9a56-c0887d1543a4)
![Image](https://github.com/user-attachments/assets/ebad9ca1-997e-4f73-80c6-785ade6460e5)

# 编译
### Linux/macOS:
```bash
git clone --recursive https://github.com/lihaoyun6/DFQ.cpp
cd DFQ.cpp
g++ -std=c++17 -O3 dfq.cpp lodepng/lodepng.cpp -pthread -o dfq
```

### Windows:
```bash
git clone --recursive https://github.com/lihaoyun6/DFQ.cpp
cd DFQ.cpp
cl /std:c++17 encrypt_cpp.cpp lodepng\lodepng.cpp
```

# 用法
```bash
$ ./dfq 
Usage:
  ./dfq encrypt in.png out.png [password]
  ./dfq decrypt in.png out.png [password]
```
