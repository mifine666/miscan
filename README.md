# 漏洞管理工具-miscan

漏洞管理工具miscan，支持漏洞管理、漏洞扫描、发包测试功能。编写本工具的目的在于帮助安全人员更方便更高效的编写漏洞规则，以方便漏洞利用和漏洞验证。

> 免责声明：此工具仅限于安全研究，用户承担因使用此工具而导致的所有法律和相关责任！作者不承担任何法律责任！

## 关于工具的特殊规则

> 工具其实越简单越好，但为了方便使用，还是有以下几点规则需要了解。

1、响应和响应头的匹配支持正则匹配。不会使用正则也没关系，可以直接匹配关键字，如果存在特殊字符，可点击转义特殊字符一键转义。

2、在响应包中可以使用 {{变量}} 来保存信息，方便后续的请求包使用。

3、设置了{{base64dec(MTIz)}}、{{hexdec(31)}}、{{unquote(\\x31)}}、{{randstr(5)}}、{{randint(1,100)}}、{{urlpath}}、{{hostname}}、{{port}}、{{http}}、{{dnslog}}标签

4、需要发送字节流的数据请使用{{base64dec(MTIz)}}、{{hexdec(31)}}、{{unquote(\\x31)}}的方式来替换，常见于反序列化，上传文件等场景。

5、需要使用dnslog检测的漏洞可以使用 {{dnslog}} 替换，工具支持自动替换并检测结果。

## ✨ 功能展示

### 漏洞管理

可以对漏洞进行增删改查操作，默认是本地模式，漏洞保存后会以文件形式保存到当前路径下，右上角可以调整模式为协作模式，密码：暂不提供。协作模式下漏洞库查看和编辑权限需要key文件，暂不提供。

[![pAWtK1g.png](https://s21.ax1x.com/2024/11/20/pAWtK1g.png)](https://imgse.com/i/pAWtK1g)

### 漏洞扫描

支持对一条或多条URL漏洞扫描，同时可以自定义一些信息，例如：自定义头、添加脏数据、启用代理、线程数、超时时间等。

[![pAWtQXj.png](https://s21.ax1x.com/2024/11/20/pAWtQXj.png)](https://imgse.com/i/pAWtQXj)

### 漏洞资产

扫描过程中检测出漏洞的资产详情会出现在漏洞资产列表。包括直接展示完整数据包，可以根据数据包判断漏洞检测结果是否准确，同时还支持搜索和导出功能。

[![pAWt87q.png](https://s21.ax1x.com/2024/11/20/pAWt87q.png)](https://imgse.com/i/pAWt87q)

### 发包测试

直接粘贴完整数据包，类似burpsuite的Repeater功能

[![pAWta3F.png](https://s21.ax1x.com/2024/11/20/pAWta3F.png)](https://imgse.com/i/pAWta3F)

## ✨编写POC

#### 编写POC时可能遇到的四种场景

场景一：发送一个请求包，匹配返回的关键字。因为是正则匹配，所以匹配特殊字符需要进行转义。例如下面这个任意文件下载漏洞。

[![pAWtyAx.png](https://s21.ax1x.com/2024/11/20/pAWtyAx.png)](https://imgse.com/i/pAWtyAx)

场景二：发送多个请求包，后面的请求需要使用到前一个响应包中的信息，例如下面这个蓝凌getLoginSessionId任意用户登录漏洞。

1、获取sessionId

[![pAWtc4K.png](https://s21.ax1x.com/2024/11/20/pAWtc4K.png)](https://imgse.com/i/pAWtc4K)

2、将sessionid添加到第二次的请求。然后获取返回cookie

[![pAWtWge.png](https://s21.ax1x.com/2024/11/20/pAWtWge.png)](https://imgse.com/i/pAWtWge)

3、将cookie替换访问

[![pAWtXvQ.png](https://s21.ax1x.com/2024/11/20/pAWtXvQ.png)](https://imgse.com/i/pAWtXvQ)

场景三：需要使用dnslog验证漏洞存在。例如下面这个XXE漏洞

[![pAWtvuj.png](https://s21.ax1x.com/2024/11/20/pAWtvuj.png)](https://imgse.com/i/pAWtvuj)

场景四：发送的请求包中存在字节流的数据。例如下面这个帆软反序列化漏洞。

[![pAWtxDs.png](https://s21.ax1x.com/2024/11/20/pAWtxDs.png)](https://imgse.com/i/pAWtxDs)

## ✨注意事项

1、在编辑POC时，请求包填写时不需要考虑Host、Referer、Origin头的值，这些值在检测时会统一帮你替换。在碰到一些GET请求的漏洞时，可以直接填写url。

2、在不指定dnslog时，存在{{dnslog}}标签的请求，工具会自动填充dnslog域名，并自动检测，结果一般都是准确的。

3、如果你不会使用正则，那么学会使用 .\*? 就可以了，它表示匹配任意个字符（除了换行符）。

4、工具提供了填充脏数据的功能，目前支持x-www-form-urlencoded、json、form-data、xml四种格式数据。

5、工具提供的多线程只用于多url批量扫描的场景，一对多时的漏洞检测为单线程。

6、发包测试功能和burpsuite的Repeater功能类似，粘贴完整的数据包上去然后点击发送即可。
