<div align="center">

# 🎵 Music Unlock · 音乐解锁工具

**纯 Python 标准库**实现的加密音频万能解锁工具：支持 **酷狗 KGM / 酷我 KWM / QQ 音乐 QMC / 网易云 NCM**，
解密输出 FLAC / MP3 / OGG 等无损文件。零第三方依赖，全离线本地运行。

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![deps](https://img.shields.io/badge/dependencies-none-success)
![formats](https://img.shields.io/badge/formats-KGM%20KWM%20QMC%20NCM-purple)
![ui](https://img.shields.io/badge/UI-Web%2B%20CLI-orange)
![license](https://img.shields.io/badge/license-MIT-green)

命令行批量解密 · 浏览器控制台（SSE 实时进度、上传即解、批量任务、输出管理）
</div>

## ✨ 特性

- **零依赖**：后端全部为 Python 标准库（`http.server` + `socketserver` 自建 Web 服务），无需安装任何包。
- **多格式一站式**：酷狗 KGM/KGMA/VPR、酷我 KWM、QQ 音乐 QMC（map/static/rc4）、网易云 NCM。
- **官方向量验证**：AES-128 FIPS-197、TEA/QMC 官方向量、KGM 官方样本全部通过内置自检。
- **Web 控制台**（SPA，暗色主题）：
  - 概览页：服务状态 / 累计解锁 / 任务进度（**SSE 实时推送**，无需轮询刷新）。
  - 文件与任务页：浏览服务器目录 → 勾选生成批量任务 → 逐文件状态、停止、结果下载（下载即删）。
  - 输出管理：解密结果一键下载 / 删除 / 清空 / **复制到任意目录**（自动处理重名）。
  - 设置页：输出目录、监听地址、并发数、覆盖/删除策略，自动保存。
- **命令行**批量解密，支持递归、覆盖、删除源文件、内置自检。
- **本地隐私**：所有解密在本机完成，数据不出本机。

## 📦 支持的格式

| 格式 | 说明                                        | 解密方式                                    |
|------|---------------------------------------------|---------------------------------------------|
| KGM  | 酷狗加密音乐（含 KGMA / VPR）               | LZMA 压缩大表密钥 + V2 掩码异或             |
| KGG  | 酷狗新格式（header version≥4）              | 文件内明文 audioHash → 酷狗 `KGMusicV3.db`（SQLCipher）查 ekey → TEA/QMC2 流解密 |
| KWM  | 酷我加密音乐                                | 32 字节掩码异或                             |
| QMC  | QQ 音乐（qmc0/1/2/3、mflac、mgg…）         | Map / 静态表 / RC4 三种子算法 + TEA 密钥解密 |
| NCM  | 网易云音乐（NCM 加密容器）                  | AES-128-ECB 元数据解密 + RC4 盒子解音频      |

> **KGG 新格式（version≥4）**需要酷狗密钥：上传酷狗客户端本地的
> `KGMusicV3.db`（`%APPDATA%\KuGou8\`，SQLCipher 加密的 SQLite）或导出的静态
> `kgg.key`（每行 `audioHash$ekey`），即可解开对应歌曲。旧版 `.kgm`/`.kgma`/`.vpr`
> （version=3）无需任何密钥，开箱即用。

## 🚀 快速开始

```bash
# 命令行直接解密（输出到源文件同目录）*例
python3 unlock.py "周杰伦 - 青花瓷.kgm.flac"

# 启动 Web 控制台（默认 http://127.0.0.1:8765）
python3 webui.py

# 启动后自动打开浏览器
python3 webui.py --open

# 内置自检（AES/TEA/KGM/QMC/KGG 全部官方向量）
python3 unlock.py -t
```

## 💻 命令行用法

```bash
# 指定输出目录，递归处理文件夹，跳过已存在的输出
python3 unlock.py -o ~/Music/解锁 -r ~/Music/加密

# 覆盖已存在文件，成功后删除源文件
python3 unlock.py -f -d ~/Music/加密

# 导入酷狗密钥库 / 静态 kgg.key（KGG 新格式解密必需）
python3 unlock.py --kgg-db ~/Desktop/KGMusicV3.db ~/Music/加密
python3 unlock.py --kgg-key ~/Desktop/kgg.key ~/Music/加密
```

| 参数             | 含义                                  |
|------------------|---------------------------------------|
| `-o DIR`         | 输出目录（默认：源文件所在目录）       |
| `-r`             | 递归处理输入目录                       |
| `-f`             | 覆盖已存在的输出文件                   |
| `-d`             | 解密成功后删除源文件                   |
| `-t`             | 运行内置自检后退出                     |
| `--list-formats` | 列出支持的格式                         |
| `-v`             | 输出跳过的原因                         |
| `--kgg-db FILE`  | 指定酷狗 `KGMusicV3.db`（KGG 密钥库）  |
| `--kgg-key FILE` | 指定静态映射 `kgg.key`（KGG 密钥）     |

> 不传 `--kgg-db/--kgg-key` 时也会自动查找环境变量 `KGG_DB` / `KGG_KEY`、
> WebUI 上传缓存与酷狗默认安装路径。kgg.key 为纯文本映射，可脱离 db 永久使用。

## 🌐 Web 界面

### 快速模式（上传解密）

浏览器内可拖拽/选文件上传加密音频，服务端本地解密后一键下载（结果临时保留 10 分钟，下载即删）。全程零依赖，数据不出本机。

### 管理控制台（后台服务）

```bash
python3 webui.py --daemon    # 后台守护进程常驻运行
python3 webui.py --status    # 查看服务是否在运行
python3 webui.py --stop      # 优雅停止后台服务
```

控制台为单页应用，包含四个页面：

| 页面       | 功能                                                            |
|------------|-----------------------------------------------------------------|
| 概览       | 服务状态、PID、格式支持、累计解锁文件数、最近任务（SSE 实时进度） |
| 文件与任务 | 三步流程一体：浏览/扫描服务器目录 → 勾选文件生成批量任务 → 任务列表与详情（逐文件状态、停止、结果下载） |
| 输出管理   | 已解锁文件列表：下载 / 删除 / 清空 / 复制到任意目录（自动避免覆盖重名） |
| 设置       | 输出目录、监听地址/端口、并发数、覆盖/删除源文件策略，自动保存        |

配置文件默认写在项目根目录 `config.json`（若存在旧的 `~/.music-unlock/config.json` 则沿用），
也可用环境变量 `MUSIC_UNLOCK_CONFIG` 指定其他路径。任务历史与守护日志统一保存在 `~/.music-unlock/`：

```
~/.music-unlock/
├── jobs.json     # 任务历史（逐文件状态 + 输出路径）
├── service.log   # 守护进程日志（--daemon 时 stdout 重定向至此）
└── pid           # 后台服务进程 PID
```

systemd 用户单元示例（`~/.config/systemd/user/music-unlock.service`）：

```ini
[Unit]
Description=Music Unlock Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /path/to/music/webui.py
Restart=on-failure

[Install]
WantedBy=default.target
```

## 🧪 运行测试

```bash
python3 tests/run_tests.py
python3 unlock.py -t
```

测试覆盖：AES-128 FIPS-197 向量、TEA 官方向量（mflac/mgg 密钥）、KGM 官方样本、
QMC map/static/rc4 全部官方向量、KWM/NCM 自反性、跨分块大小的 KGM 一致性，
以及 KGG 的 db 页派生官方向量、SQLCipher 库加密往返与 QMC2（MAP/RC4）音区往返。

## ✅ 已验证范围（重要）

本项目作者仅持有**酷狗（KuGou）**账号，因此：

| 格式 | 内置自检（官方向量） | 真实加密文件实测（WebUI / CLI） |
|------|:----:|:----:|
| 酷狗 KGM/KGMA/VPR | ✅ 通过 | ✅ 已用真实 `.kgm` 文件完整验证（命令行、WebUI 上传/下载、SSE 任务、输出管理均实测） |
| 酷狗 KGG v5 | ✅ 通过（db 派生向量 + 往返） | ⚠️ 算法与官方逐行一致、链路自检全绿，但解密需真实 `KGMusicV3.db`，待你上传密钥库后连通验证 |
| 酷我 KWM | ✅ 通过 | ⚠️ 未实测（无账号） |
| QQ 音乐 QMC | ✅ 通过（map/static/rc4） | ⚠️ 未实测（无账号） |
| 网易云 NCM | ✅ 通过（自反性） | ⚠️ 未实测（无账号） |

> 说明：KWM / QMC / NCM 的解密算法已按开源实现逐行移植并通过对应的官方测试向量自检，
> 但作者未使用真实平台的加密文件在工具内实际解码验证。**若你使用这几类格式，请先拿 1-2 个
> 自己的文件在 WebUI 或命令行实测，确认输出可播放后再批量处理正式文件。** 如遇到问题，欢迎提
> [Issue](https://github.com/zqy857/music-unlock/issues) 反馈（附上脱敏后的文件信息）。

## 📁 包结构

```
music_unlock/
├── core.py        # 统一解密管线（检测→解密→嗅探→重命名）
├── cli.py         # 命令行入口
├── kgg_keys.py    # KGG 密钥映射全局管理（db/kgg.key/env/自动发现）
├── sniff.py       # 音频格式嗅探
├── crypto/
│   ├── aes.py     # 纯 Python AES-128-ECB/CBC（可选 pycryptodome 加速）
│   ├── tea.py     # TEA 加解密 + QMC/KGG ekey（V1/V2）处理
│   └── kgg_db.py  # KGMusicV3.db（SQLCipher）解密 + kgg.key 导出/导入
├── formats/
│   ├── kgm.py     # 酷狗 KGM/KGMA/VPR（并分流 v5 → kgg）
│   ├── kgg.py     # 酷狗 KGG 新格式（v5，audioHash→ekey→QMC2）
│   ├── kwm.py     # 酷我
│   ├── qmc.py     # QQ 音乐
│   └── ncm.py     # 网易云
└── assets/        # 酷狗大表密钥（lzma 压缩，KGM 解密必需）

webui.py            # http.server 服务端：控制台 API + 上传快速解密 + 守护进程
webui.html          # 前端 SPA（暗色主题控制台：概览/文件/任务/设置/日志）
```

## 🙏 致谢与算法来源

本工具不含任何自研破解，**所有解密算法均为开源社区逆向成果**，本项目只是把参考实现逐行翻译成 Python 并用其官方向量验证。

- **[unlock-music](https://git.unlock-music.dev/um/web)** / **[unlock-music/cli](https://git.unlock-music.dev/um/cli)**（MIT）：QMC、KWM、NCM、KGM 及 KGG 的算法实现与测试向量，全部从 Go 版 CLI 逐行移植（含 `pc_kugou_db` 的 SQLCipher 页派生与页 1 校验）；kugou 公钥最初亦由其提供。
- **[skxxxkx666/Kugo-Music-Converter](https://github.com/skxxxkx666/Kugo-Music-Converter)** / **[PineVigil/kugou-decryptor](https://github.com/PineVigil/kugou-decryptor)**（Go / Python）：KGG v5 与 `KGMusicV3.db` 解密的交叉对照实现。
- **孤心浪子的博客《酷狗音乐 kgm 解密》**（[cnblogs.com/KMBlog/p/6877752.html](https://www.cnblogs.com/KMBlog/p/6877752.html)）：KGM 算法原理的公开来源。
- **[ghtz08/kuguo-kgm-decoder](https://github.com/ghtz08/kuguo-kgm-decoder)**（Rust）：KGM 参考实现与 `kugou_key.xz` 大表密钥的来源。
- TEA 参考 [golang.org/x/crypto/tea](https://pkg.go.dev/golang.org/x/crypto/tea)（BSD）。

向以上所有逆向与开源贡献者致敬。

## ⚠️ 注意与免责声明

- 仅用于解密你**拥有合法版权**的音频文件。
- 各平台加密算法与密钥大表均来自上表开源项目，版权归原作者；请遵守其开源协议。
- **免责声明**：本工具仅用于学习交流与备份解锁个人已购/已下载的合法音乐文件。请勿用于下载、破解或传播未授权的盗版内容。因使用本工具产生的一切法律后果由使用者自行承担，与项目作者无关。
- KGM 依赖 `assets/kugou_key.xz`，请勿删除。
- 输出文件名按音频内容嗅探扩展名（FLAC/MP3/OGG 等），并剥离 `.kgm`/`.qmc` 等尾部标记。
