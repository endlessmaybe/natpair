# 搜索入口与维护

本页记录仓库搜索入口的维护方式，不承诺搜索排名或访问增长。2026-10-17 检查时，仓库 About 的简介、主页和 Topics 均为空；默认仓库搜索 `user:endlessmaybe tailscale` 未找到本项目。它说明搜索匹配入口缺失，不是全站排名或流量归因结论。

## 准确描述项目

- 名称保持 `natpair`，不破坏已有链接。
- 简介同时说明 Windows、UDP hole punching / NAT traversal、Tailscale、Minecraft Java，以及中文的多人 UDP 打洞 / 内网穿透 / MC 联机辅助。
- 默认 README 用中文解释主要使用场景，提供英文摘要和独立 [英文指南](../README.en.md)。配置模板、自己的协调服务、真实联网边界都要保留。
- About 主页指向 [下载页](https://github.com/endlessmaybe/natpair/releases/latest)，让新用户直接找到完整 Windows 包。
- Topics 只用实际能力相关词；不标注尚未提供的平台、协议、游戏版本或许可证。

当前建议的 Topics：`nat-traversal`、`udp-hole-punching`、`hole-punching`、`nat`、`udp`、`tailscale`、`p2p`、`peer-to-peer`、`minecraft`、`minecraft-java`、`lan-gaming`、`multiplayer`、`windows`、`python`、`networking`。

## 检查是否被找到

GitHub 默认仓库搜索匹配名称、简介与 Topics；全文 README 查询需要显式加 `in:readme`。示例：

```text
natpair in:name
user:endlessmaybe tailscale
user:endlessmaybe "内网穿透"
user:endlessmaybe topic:udp-hole-punching
user:endlessmaybe minecraft in:readme
```

修改后先复核 About 和默认分支文件实际生效，再检查搜索查询。索引可能延迟，不能因为一次搜索没有出现就不断更换仓库名、堆叠标签或制造提交。

规则依据：[GitHub 仓库搜索](https://docs.github.com/en/search-github/searching-on-github/searching-for-repositories)、[Topics](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics)、[README](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes)。

## 看真实效果

在仓库 Insights → Traffic 按可比时间窗口记录访问人数、访问量、克隆人数、来源页面和热门内容；同时参考 Release 下载数及真实反馈。GitHub 的 Traffic 不是搜索曝光或搜索点击率报表，克隆数也不能直接解释为真实使用人数。

后续用实际多人网络测试、清晰的演示截图和具体问题的排错文章吸引目标用户；没有取得证据前不写“全 NAT 成功”“零延迟”之类承诺。若要采用项目自身的开源许可证，由维护者明确选定并确认授权范围，不能为了进入 `license:` 搜索擅自加 MIT。

本次仅调整仓库展示与文档，不更换 v1.2.0 二进制或既有校验文件；Release 内旧文档与默认分支文档的更新时间可能不同。
