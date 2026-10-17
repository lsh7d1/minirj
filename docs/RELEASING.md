# 发布与交付

在开发机或 CI runner 上执行，产出一份可离线源码安装的交付目录。

## 环境

Linux、Python 3.10+、`unshare`、user/net/PID namespace、可执行临时目录，
以及 `/proc`、Unix socket、`/bin/sh`、`sleep`（测试使用）。

## 测试

```bash
(
  set -eu
  python3 -B -m unittest discover -s tests -v
  python3 -B -m unittest discover -s tools/tests -v
)
```

全部用例通过。部分回归用例需要仓库外的本地输入；缺失时这些用例跳过。

## 安装验收

```bash
(
  set -eu
  python3 tools/check_install.py
)
```

验证内容：zipapp 构建、CLI、资源 SHA256、缺失/损坏负向用例。
通过标准：退出码 0，输出 `PASS: source -> zipapp -> isolated import`。

## 组装交付目录

交付内容：完整 `minirj/` 源码、`deploy/`、根目录 `deploy.sh`；可选 `tests/`。
`deploy.sh install` 会用目录内的 `deploy/build_zipapp.py` 构建 `minirj.pyz`。

```bash
(
  set -eu
  VERSION=$(python3 -c 'import minirj; print(minirj.__version__)')
  OUT="dist/offline/minirj-$VERSION"
  test ! -e "$OUT"
  install -d "$OUT/tests"
  cp README.md deploy.sh "$OUT/"
  cp -R minirj deploy "$OUT/"
  cp tests/*.py "$OUT/tests/"
  cp -R docs "$OUT/docs"
  tar -czf "$OUT-offline.tar.gz" -C dist/offline "minirj-$VERSION"
)
```

目标机依赖：Python >=3.10、systemd、NetworkManager internal DHCP、polkit。

## 复核安装

在隔离、无外网环境中解开交付物，执行
`sudo bash ./deploy.sh install --interface ...`；或直接构建并运行：

```bash
python3 -I deploy/build_zipapp.py --source minirj --entry deploy/zipapp_main.py --output /tmp/minirj.pyz
python3 -I /tmp/minirj.pyz --version
python3 -B -m unittest discover -s tests
```

确认 CLI 可用、测试通过。
