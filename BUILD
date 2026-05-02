genrule(
    name = "pyng_bin",
    srcs = glob(["app/**/*.py", "doc/**/*.yaml"]),
    outs = ["pyng"],
    cmd = """
        /opt/homebrew/bin/nuitka \
            --onefile \
            --include-data-dir=doc=doc \
            --onefile-tempdir-spec=/tmp/nuitka-pyng \
            --no-progressbar \
            --assume-yes-for-downloads \
            --no-deployment-flag=self-execution \
            --output-dir=$$(dirname $(location pyng)) \
            --output-filename=pyng \
            $(location app/main.py)
    """,
    local = 1,
    visibility = ["//visibility:public"],
)
