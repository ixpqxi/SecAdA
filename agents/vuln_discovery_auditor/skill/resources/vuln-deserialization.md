# 反序列化漏洞审计指南 (Deserialization)

反序列化漏洞的本质在于：程序接受了攻击者构造的序列化字符串（对象形态），并在将其恢复为内存对象的过程中，自动触发了危险的方法（Magic Methods）。

## 1. PHP 反序列化
- **Sink 特征**：`unserialize()` 函数。
- **漏洞触发原理 (魔术方法)**：
  寻找代码中是否定义了以下魔术方法，并在方法内部执行了危险操作（如文件删除、执行命令）：
  - `__wakeup()`：在反序列化时立即被调用。
  - `__destruct()`：对象被销毁时调用。
  - `__toString()`：对象被当成字符串输出时调用。
  - `__construct()`：(注意：常规反序列化不触发，但常作为 POP 链的起点)。
- **POP 链审计**：即使当前类没有危险操作，攻击者也可以通过控制类属性，触发另一个类的方法，形成利用链。必须通读系统内所有可能被实例化的类。

## 2. Java 反序列化 (概念延伸)
- **Sink 特征**：`ObjectInputStream.readObject()`, 以及 Fastjson、Jackson 等 JSON 库的 `parseObject()`, `readValue()`。
- **审计策略**：
  - 检查系统是否暴露了接收序列化流的接口（如 RMI 服务、基于原生序列化的 RPC）。
  - 检查使用的第三方组件组件版本（如 Apache Commons Collections, Fastjson < 1.2.68）是否存在公开的反序列化 Gadget 链。
- **安全规范**：严禁直接反序列化不可信数据。若必须使用，应采取白名单机制限制可被反序列化的类（如 Java 的 `ObjectInputFilter`）。
