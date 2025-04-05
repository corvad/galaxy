# Galaxy
This is mainly a project that I was working on in my free time.
Mainly the goal was to learn go and at the same time I was also looking into post quantum crypto so things kind of just blended and I ended up accidentally writing some golang to implement an alternaitve to rsa.
The algorithms I used were ML-KEM-1024 or commonly known as Kyber and I used AES-256 for post key exchange communication. Both of these algorithms should be resilient to Shor's algorithm and in an ideal scenario would already be widely used because of store now decrypt later attacks.
It even has file functionality to save the keys. I put a simple example in the main, it literally just creates the two keys then does a "key exchange". Feel free to use this code for your own projects. It was mainly just a learning experience for me. Probably wont do much with it in the future.
Pretty simple to run just
```
go run main.go
```
The module is called galaxy and the package containing the code is called concorde.
