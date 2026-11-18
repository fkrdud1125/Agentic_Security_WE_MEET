import yaml
# ruleid: vs-py-yaml
yaml.load(data, Loader=yaml.Loader)
# ok: vs-py-yaml
yaml.safe_load(data)
