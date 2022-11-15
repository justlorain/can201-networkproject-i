import hashlib
import json


class login_info:
    def __init__(self, username):
        self.username = username
        self.password = self.do_md5(username)

    @staticmethod
    def do_md5(password):
        hl = hashlib.md5()
        hl.update(password.encode(encoding='utf8'))
        md5 = hl.hexdigest()
        return str(md5)


def main():
    l = login_info("2037381")
    l_json = json.dumps(l.__dict__)
    print(l_json)


if __name__ == '__main__':
    main()
