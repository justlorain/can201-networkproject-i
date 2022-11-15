import hashlib

text="张三"
hl=hashlib.md5()
hl.update(text.encode(encoding='utf8'))
md5=hl.hexdigest()
print("加密结果："+str(md5))