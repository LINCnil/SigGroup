import yaml

def load_urls_from_yaml():
    with open("parameters.yaml") as file:
        urls = yaml.load(file, Loader=yaml.FullLoader)

    return urls