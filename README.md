# sm-tools
采用pyqt5与python3.7.4实现了以下商密功能： 

 * 1、sm2密钥对生成，sm2加密、解密、签名验签；
 
 * 2、sm3哈希计算；
 
 * 3、sm4带填充与不带填充的ecb/cbc模式的加解密。

文件说明：
 * 1、pack.py为发布脚本；

 * 2、sm_tools_dist.py集成了界面的python代码；

 * 3、sm_tools.py依赖sm_cipher_tools.ui文件；

 * 4、gmssl为不带界面sm2/3/4基础算法库
 
python工具打包步骤：
 * 1、安装python，可安装python3.7.4
 * 2、用pip3安装pyqt5_sip、pyqt5 (pip3依赖openssl进行ssl通信)
 * 3、用pip3安装pyinstaller
 * 4、运行pack.py脚本或使用pyinstaller命令行打包
