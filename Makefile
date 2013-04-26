JAVAC=javac
API=burp_extender_api.zip
JAR=burp-oauth.jar
CLASSES=$(shell find . -name '*.java' | sed s/java/class/)

$(JAR): $(CLASSES)
	jar cmf /dev/null $@ $<

%.class: %.java
	$(JAVAC) -classpath $(API) $<

clean:
	rm -f $(CLASSES) $(JAR)

.PHONY: clean
