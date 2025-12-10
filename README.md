# DFQ.cpp
"大番茄图片混淆"的C++实现  

# 预览 
<p align="center">
	<img alt="image" src="./preview.png"/>
</p>

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
