# 基于机器学习的WAF

## 项目背景
本项目是我大学毕业设计，参考自github上大佬已经完成的WAF并进行了一定的拓展与修改。由于本人才疏学浅，目前该WAF仅能够在Linux系统下运行，并且检测攻击行为较少，预计后期版本迭代（如果有的话）将增加这些内容。

### 功能列表
- 攻击分析
- 透明代理
- 报文嗅探
- 前端展示

## 项目部署

### 环境需求
    python >= 3.6.0
    Manjaro Gnome 21.1.6 或其他 Linux系统

### 项目部署
在项目的根目录打开命令行输入 `source activate setup.sh` 脚本将自动安装所需的python模块并启动项目，系统缺少模块则需要根据提示手动安装。

## 未来计划

- 反向代理
- 并发处理
- 代码重构
- java版本开发

## 项目参考链接

`https://github.com/vladan-stojnic/ML-based-WAF`  
训练数据以及数据处理代码可私信作者Gmail邮箱 scentedtea210@gmail.com
