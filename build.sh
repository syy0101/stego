echo "clearing bin/"
if [ ! -d "bin/" ]; then
    mkdir bin
else
    rm -r bin/*
fi

echo "building"
javac -sourcepath src/ -d bin/ -classpath lib/JavaReedSolomon-master.jar:lib/bcprov-jdk18on-171.jar src/stego/util/CommandLineInterface.java

echo "unpacking dependency libraries"
cd bin
jar xf ../lib/bcprov-jdk18on-171.jar org/
jar xf ../lib/JavaReedSolomon-master.jar com/
cd ..

echo "backing up the old jar"
if [ -f stego.jar ]; then
    mv stego.jar stego.jar.bak
fi

echo "creating jar"
jar cfe stego.jar stego.util.CommandLineInterface -C bin .

echo "cleaning doc/"
if [ -d "doc/" ]; then
    rm -r doc/*
fi

echo "creating javadoc"
javadoc -quiet -package -sourcepath src/ -d doc/ -classpath lib/JavaReedSolomon.jar:lib/bcprov-jdk18on-171.jar:bin/ stego.io stego.ecc stego.crypto stego.util 
