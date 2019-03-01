# iPAObfuscator
to Obfuscate iPA which contain bitcode， 是一款针对二进制的加固工具，底层使用的clang是ollvm编译的。

# usage
python main.py  bctest -o bctest_new


# 注意事项
此版本只是demo版，仅供技术研究，想使用更全面的功能和更优质的服务请点击[商业版](https://github.com/godshield/iOSObfuscator) 
# 联系我们
有任何疑问都可以联系我们

邮箱:shendun@god-shield.com

QQ:2667069150
  
QQ用户交流①群:786457705

[神盾官网](http://www.god-shield.com)


# 自助免费服务请访问 [免费加固服务](https://github.com/godshield/iOSObfuscator)

# 加固对比
* 2.使用的混淆参数如下:
    -mllvm -bcf -mllvm -bcf_loop=3 -mllvm -bcf_prob=40 -mllvm-fla -mllvm -split -mllvm -split_num=2
* 3.加固效果如下：


  加固前：
  ![LOGO](https://github.com/godshield/iPAObfuscator/blob/master/before.png)

  加固后:
  ![LOGO](https://github.com/godshield/iPAObfuscator/blob/master/after.png)