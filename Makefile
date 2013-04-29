JAVAC=javac
API=burp_extender_api.zip
SIGNPOST=signpost-core-1.2.1.2.jar
JAR=burp-oauth.jar
JUNIT=junit-4.11.jar:hamcrest-core-1.3.jar
CLASSPATH=$(SIGNPOST):$(JUNIT):.
CLASSES=$(shell find . -name '*.java' | sed s/java/class/)

$(JAR): $(CLASSES)
	cp $(SIGNPOST) $@
	jar cf $@ $^

test: burp/BurpHttpRequestWrapper.class burp/OAuthTest.class
	java -cp $(CLASSPATH) org.junit.runner.JUnitCore burp.OAuthTest

%.class: %.java
	$(JAVAC) -classpath $(CLASSPATH):. $<

clean:
	rm -f $(CLASSES) $(JAR)

.PHONY: clean
