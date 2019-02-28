# iPAObfuscator
to Obfuscate iPA which contain bitcode， 是一款针对二进制的加固工具，底层使用的clang是ollvm编译的。

# usage
python main.py  bctest -o bctest_new


# 注意事项
  * 此版本只是demo版，仅供技术研究，想使用商业版更全面更详细的功能请阅读另外一个项目:https://github.com/godshield/iOSObfuscator 
# 联系我们
  有任何疑问都可以联系我们

  邮箱:shendun@god-shield.com

  QQ:2667069150
  
  QQ用户交流①群:786457705

# 自助免费服务请访问 [神盾科技官网](http://www.god-shield.com)

# 加固对比
* 2.使用的混淆参数如下:
    -mllvm -bcf -mllvm -bcf_loop=3 -mllvm -bcf_prob=40 -mllvm-fla -mllvm -split -mllvm -split_num=2
* 3.加固效果如下：


  加固前：
  ![LOGO](https://github.com/godshield/iPAObfuscator/blob/master/before.png)

  加固后:
  ![LOGO](https://github.com/godshield/iPAObfuscator/blob/master/after.png)