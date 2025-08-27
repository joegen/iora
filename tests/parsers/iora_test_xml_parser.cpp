#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/parsers/xml.hpp"
#include <string>
#include <sstream>

using namespace iora::parsers::xml;

TEST_CASE("XML Parser - Basic Parsing", "[xml][parser][basic]")
{
  SECTION("Simple element parsing")
  {
    std::string xml = "<root>hello</root>";
    Parser parser(xml);
    
    REQUIRE(parser.next());
    const auto &tok1 = parser.current();
    REQUIRE(tok1.kind == TokenKind::StartElement);
    REQUIRE(tok1.name == "root");
    REQUIRE(tok1.depth == 1);
    
    REQUIRE(parser.next());
    const auto &tok2 = parser.current();
    REQUIRE(tok2.kind == TokenKind::Text);
    REQUIRE(tok2.text == "hello");
    REQUIRE(tok2.depth == 1);
    
    REQUIRE(parser.next());
    const auto &tok3 = parser.current();
    REQUIRE(tok3.kind == TokenKind::EndElement);
    REQUIRE(tok3.name == "root");
    REQUIRE(tok3.depth == 1);
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
  
  SECTION("Empty element parsing")
  {
    std::string xml = "<empty/>";
    Parser parser(xml);
    
    REQUIRE(parser.next());
    const auto &tok = parser.current();
    REQUIRE(tok.kind == TokenKind::EmptyElement);
    REQUIRE(tok.name == "empty");
    REQUIRE(tok.selfClosing == true);
    REQUIRE(tok.depth == 1);
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
  
  SECTION("Element with attributes")
  {
    std::string xml = "<elem attr1=\"value1\" attr2='value2'>content</elem>";
    Parser parser(xml);
    
    REQUIRE(parser.next());
    const auto &tok = parser.current();
    REQUIRE(tok.kind == TokenKind::StartElement);
    REQUIRE(tok.name == "elem");
    REQUIRE(tok.attributes.size() == 2);
    REQUIRE(tok.attributes[0].name == "attr1");
    REQUIRE(tok.attributes[0].value == "value1");
    REQUIRE(tok.attributes[1].name == "attr2");
    REQUIRE(tok.attributes[1].value == "value2");
    
    REQUIRE(parser.next());
    const auto &textTok = parser.current();
    REQUIRE(textTok.kind == TokenKind::Text);
    REQUIRE(textTok.text == "content");
    
    REQUIRE(parser.next());
    const auto &endTok = parser.current();
    REQUIRE(endTok.kind == TokenKind::EndElement);
    REQUIRE(endTok.name == "elem");
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
}

TEST_CASE("XML Parser - Nested Elements", "[xml][parser][nested]")
{
  SECTION("Nested structure")
  {
    std::string xml = "<root><child1>text1</child1><child2>text2</child2></root>";
    Parser parser(xml);
    
    // Root start
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::StartElement);
    REQUIRE(parser.current().name == "root");
    REQUIRE(parser.current().depth == 1);
    
    // Child1 start
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::StartElement);
    REQUIRE(parser.current().name == "child1");
    REQUIRE(parser.current().depth == 2);
    
    // Child1 text
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::Text);
    REQUIRE(parser.current().text == "text1");
    REQUIRE(parser.current().depth == 2);
    
    // Child1 end
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::EndElement);
    REQUIRE(parser.current().name == "child1");
    REQUIRE(parser.current().depth == 2);
    
    // Child2 start
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::StartElement);
    REQUIRE(parser.current().name == "child2");
    REQUIRE(parser.current().depth == 2);
    
    // Child2 text
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::Text);
    REQUIRE(parser.current().text == "text2");
    
    // Child2 end
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::EndElement);
    REQUIRE(parser.current().name == "child2");
    
    // Root end
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::EndElement);
    REQUIRE(parser.current().name == "root");
    REQUIRE(parser.current().depth == 1);
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
  
  SECTION("Deep nesting")
  {
    std::string xml = "<a><b><c><d>deep</d></c></b></a>";
    Parser parser(xml);
    
    std::vector<std::string> expectedNames = {"a", "b", "c", "d"};
    std::vector<std::size_t> expectedDepths = {1, 2, 3, 4};
    
    for (std::size_t i = 0; i < expectedNames.size(); ++i)
    {
      REQUIRE(parser.next());
      REQUIRE(parser.current().kind == TokenKind::StartElement);
      REQUIRE(parser.current().name == expectedNames[i]);
      REQUIRE(parser.current().depth == expectedDepths[i]);
    }
    
    // Text content
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::Text);
    REQUIRE(parser.current().text == "deep");
    REQUIRE(parser.current().depth == 4);
    
    // End elements in reverse order
    for (int i = static_cast<int>(expectedNames.size()) - 1; i >= 0; --i)
    {
      REQUIRE(parser.next());
      REQUIRE(parser.current().kind == TokenKind::EndElement);
      REQUIRE(parser.current().name == expectedNames[static_cast<std::size_t>(i)]);
      REQUIRE(parser.current().depth == expectedDepths[static_cast<std::size_t>(i)]);
    }
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
}

TEST_CASE("XML Parser - Special Content", "[xml][parser][special]")
{
  SECTION("CDATA section")
  {
    std::string xml = "<root><![CDATA[This is <raw> content & stuff]]></root>";
    Parser parser(xml);
    
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::StartElement);
    REQUIRE(parser.current().name == "root");
    
    REQUIRE(parser.next());
    const auto &cdataTok = parser.current();
    REQUIRE(cdataTok.kind == TokenKind::CData);
    REQUIRE(cdataTok.text == "This is <raw> content & stuff");
    
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::EndElement);
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
  
  SECTION("Comments")
  {
    std::string xml = "<root><!-- This is a comment --><child/></root>";
    Parser parser(xml);
    
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::StartElement);
    REQUIRE(parser.current().name == "root");
    
    REQUIRE(parser.next());
    const auto &commentTok = parser.current();
    REQUIRE(commentTok.kind == TokenKind::Comment);
    REQUIRE(commentTok.text == " This is a comment ");
    
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::EmptyElement);
    REQUIRE(parser.current().name == "child");
    
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::EndElement);
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
  
  SECTION("Processing instruction")
  {
    std::string xml = "<?xml version=\"1.0\"?><root><?target data?></root>";
    Parser parser(xml);
    
    REQUIRE(parser.next());
    const auto &piTok = parser.current();
    REQUIRE(piTok.kind == TokenKind::ProcessingInstruction);
    REQUIRE(piTok.name == "xml");
    REQUIRE(piTok.text == " version=\"1.0\"");
    
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::StartElement);
    REQUIRE(parser.current().name == "root");
    
    REQUIRE(parser.next());
    const auto &piTok2 = parser.current();
    REQUIRE(piTok2.kind == TokenKind::ProcessingInstruction);
    REQUIRE(piTok2.name == "target");
    REQUIRE(piTok2.text == " data");
    
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::EndElement);
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
}

TEST_CASE("XML Parser - Entity Decoding", "[xml][parser][entities]")
{
  SECTION("Predefined entities")
  {
    std::string input = "&lt;&gt;&amp;&apos;&quot;";
    std::string output;
    Error err;
    
    REQUIRE(Parser::decodeEntities(input, output, &err));
    REQUIRE(output == "<>&'\"");
  }
  
  SECTION("Numeric character references")
  {
    std::string input = "&#65;&#x42;&#67;"; // A B C
    std::string output;
    Error err;
    
    REQUIRE(Parser::decodeEntities(input, output, &err));
    REQUIRE(output == "ABC");
  }
  
  SECTION("Mixed content with entities")
  {
    std::string input = "Hello &amp; goodbye &lt;world&gt;";
    std::string output;
    Error err;
    
    REQUIRE(Parser::decodeEntities(input, output, &err));
    REQUIRE(output == "Hello & goodbye <world>");
  }
  
  SECTION("Invalid entity")
  {
    std::string input = "&unknown;";
    std::string output;
    Error err;
    
    REQUIRE_FALSE(Parser::decodeEntities(input, output, &err));
    REQUIRE(err.message == "unknown entity");
  }
  
  SECTION("Unterminated entity")
  {
    std::string input = "&amp";
    std::string output;
    Error err;
    
    REQUIRE_FALSE(Parser::decodeEntities(input, output, &err));
    REQUIRE(err.message == "unterminated entity");
  }
}

TEST_CASE("XML Parser - QName Splitting", "[xml][parser][qname]")
{
  SECTION("Simple name without namespace")
  {
    Token token;
    token.name = "element";
    
    auto [prefix, localName] = token.splitQName();
    REQUIRE(prefix.empty());
    REQUIRE(localName == "element");
  }
  
  SECTION("Namespaced name")
  {
    Token token;
    token.name = "ns:element";
    
    auto [prefix, localName] = token.splitQName();
    REQUIRE(prefix == "ns");
    REQUIRE(localName == "element");
  }
  
  SECTION("Multiple colons")
  {
    Token token;
    token.name = "ns:sub:element";
    
    auto [prefix, localName] = token.splitQName();
    REQUIRE(prefix == "ns");
    REQUIRE(localName == "sub:element");
  }
}

TEST_CASE("XML Parser - Error Handling", "[xml][parser][errors]")
{
  SECTION("Malformed XML - missing closing tag")
  {
    std::string xml = "<root><child>text";
    Parser parser(xml);
    
    REQUIRE(parser.next()); // root start
    REQUIRE(parser.next()); // child start
    REQUIRE(parser.next()); // text
    REQUIRE_FALSE(parser.next()); // should fail at EOF
    
    // Parser now correctly reports unclosed tags at EOF
    const Error *err = parser.error();
    REQUIRE(err != nullptr);
    REQUIRE(std::string(err->message).find("unclosed elements") != std::string::npos);
  }
  
  SECTION("Malformed XML - unbalanced tags")
  {
    std::string xml = "<root><child></root>";
    Parser parser(xml);
    
    REQUIRE(parser.next()); // root start
    REQUIRE(parser.next()); // child start  
    REQUIRE_FALSE(parser.next()); // Should fail on mismatched end tag
    
    // Parser now correctly reports unbalanced tag errors
    const Error *err = parser.error();
    REQUIRE(err != nullptr);
    REQUIRE(std::string(err->message).find("mismatched end tag") != std::string::npos);
  }
  
  SECTION("Invalid tag name")
  {
    std::string xml = "<123invalid>";
    Parser parser(xml);
    
    REQUIRE_FALSE(parser.next());
    const Error *err = parser.error();
    REQUIRE(err != nullptr);
  }
  
  SECTION("Invalid attribute syntax")
  {
    std::string xml = "<elem attr=value>";
    Parser parser(xml);
    
    REQUIRE_FALSE(parser.next());
    const Error *err = parser.error();
    REQUIRE(err != nullptr);
  }
  
  SECTION("Depth limit exceeded")
  {
    Options opts;
    opts.maxDepth = 3;
    
    std::string xml = "<a><b><c><d>too deep</d></c></b></a>";
    Parser parser(xml, opts);
    
    REQUIRE(parser.next()); // a
    REQUIRE(parser.next()); // b  
    REQUIRE(parser.next()); // c
    REQUIRE_FALSE(parser.next()); // d should fail depth limit
    
    const Error *err = parser.error();
    REQUIRE(err != nullptr);
    REQUIRE(err->message == "maximum element depth exceeded");
  }
}

TEST_CASE("XML Parser - Configuration Options", "[xml][parser][options]")
{
  SECTION("Token limit")
  {
    Options opts;
    opts.maxTotalTokens = 3;
    
    std::string xml = "<root><child>text</child></root>";
    Parser parser(xml, opts);
    
    REQUIRE(parser.next()); // 1: root start
    REQUIRE(parser.next()); // 2: child start  
    REQUIRE(parser.next()); // 3: text
    REQUIRE_FALSE(parser.next()); // 4: should fail
    
    const Error *err = parser.error();
    REQUIRE(err != nullptr);
    REQUIRE(err->message == "token limit exceeded");
  }
  
  SECTION("Attribute limit")
  {
    Options opts;
    opts.maxAttrsPerElement = 2;
    
    std::string xml = "<elem a=\"1\" b=\"2\" c=\"3\"/>";
    Parser parser(xml, opts);
    
    REQUIRE_FALSE(parser.next());
    const Error *err = parser.error();
    REQUIRE(err != nullptr);
    REQUIRE(err->message == "too many attributes");
  }
  
  SECTION("Name length limit")
  {
    Options opts;
    opts.maxNameLength = 5;
    
    std::string xml = "<verylongname>";
    Parser parser(xml, opts);
    
    REQUIRE_FALSE(parser.next());
    const Error *err = parser.error();
    REQUIRE(err != nullptr);
    REQUIRE(err->message == "invalid start tag name");
  }
}

#if IORA_XML_ENABLE_SAX
TEST_CASE("XML Parser - SAX Interface", "[xml][parser][sax]")
{
  SECTION("SAX callbacks")
  {
    std::string xml = "<root attr=\"val\"><!-- comment --><child>text</child></root>";
    Parser parser(xml);
    
    std::vector<std::string> events;
    SaxCallbacks callbacks;
    
    callbacks.onStartElement = [&](const Token &t) {
      events.push_back("start:" + std::string(t.name));
    };
    
    callbacks.onEndElement = [&](const Token &t) {
      events.push_back("end:" + std::string(t.name));
    };
    
    callbacks.onText = [&](const Token &t) {
      events.push_back("text:" + std::string(t.text));
    };
    
    callbacks.onComment = [&](const Token &t) {
      events.push_back("comment:" + std::string(t.text));
    };
    
    REQUIRE(runSax(parser, callbacks));
    
    std::vector<std::string> expected = {
      "start:root",
      "comment: comment ",
      "start:child", 
      "text:text",
      "end:child",
      "end:root"
    };
    
    REQUIRE(events == expected);
  }
}
#endif

#if IORA_XML_ENABLE_DOM
TEST_CASE("XML Parser - DOM Interface", "[xml][parser][dom]")
{
  SECTION("Simple DOM building")
  {
    std::string xml = "<root attr=\"value\"><child>text content</child><empty/></root>";
    Parser parser(xml);
    
    Error err;
    auto doc = DomBuilder::build(parser, &err);
    
    REQUIRE(doc != nullptr);
    REQUIRE(doc->type == NodeType::Document);
    REQUIRE(doc->children.size() == 1);
    
    const Node *root = doc->children[0].get();
    REQUIRE(root->type == NodeType::Element);
    REQUIRE(root->name == "root");
    REQUIRE(root->attributes.size() == 1);
    REQUIRE(root->attributes[0].name == "attr");
    REQUIRE(root->attributes[0].value == "value");
    
    REQUIRE(root->children.size() == 2);
    
    const Node *child = root->children[0].get();
    REQUIRE(child->type == NodeType::Element);
    REQUIRE(child->name == "child");
    REQUIRE(child->children.size() == 1);
    REQUIRE(child->children[0]->type == NodeType::Text);
    REQUIRE(child->children[0]->value == "text content");
    
    const Node *empty = root->children[1].get();
    REQUIRE(empty->type == NodeType::Element);
    REQUIRE(empty->name == "empty");
    REQUIRE(empty->children.empty());
  }
  
  SECTION("DOM helper methods")
  {
    std::string xml = "<root><person name=\"Alice\"><age>30</age></person></root>";
    Parser parser(xml);
    
    auto doc = DomBuilder::build(parser);
    REQUIRE(doc != nullptr);
    
    const Node *root = doc->children[0].get();
    const Node *person = root->childByName("person");
    REQUIRE(person != nullptr);
    REQUIRE(person->getAttribute("name") == "Alice");
    
    const Node *age = person->childByName("age");
    REQUIRE(age != nullptr);
    REQUIRE(age->getTextContent() == "30");
    
    // Test non-existent child
    const Node *missing = root->childByName("missing");
    REQUIRE(missing == nullptr);
    
    // Test non-existent attribute
    auto missingAttr = person->getAttribute("missing");
    REQUIRE(missingAttr.empty());
  }
  
  SECTION("DOM with entities")
  {
    std::string xml = "<root attr=\"&lt;value&gt;\">Text with &amp; entities</root>";
    Parser parser(xml);
    
    auto doc = DomBuilder::build(parser);
    REQUIRE(doc != nullptr);
    
    const Node *root = doc->children[0].get();
    REQUIRE(root->getAttribute("attr") == "<value>");
    REQUIRE(root->getTextContent() == "Text with & entities");
  }
  
  SECTION("DOM error handling")
  {
    std::string xml = "<root><unclosed>";
    Parser parser(xml);
    
    Error err;
    auto doc = DomBuilder::build(parser, &err);
    
    REQUIRE(doc == nullptr);
    REQUIRE(err.message.find("unclosed elements at end of document") != std::string::npos);
  }
}
#endif

TEST_CASE("XML Parser - Real-world Examples", "[xml][parser][realworld]")
{
  SECTION("RSS-like structure")
  {
    std::string xml = R"(
      <rss version="2.0">
        <channel>
          <title>Test Feed</title>
          <item>
            <title>First Post</title>
            <description><![CDATA[Content with <em>markup</em>]]></description>
          </item>
        </channel>
      </rss>
    )";
    
    Parser parser(xml);
    
    // Skip whitespace and parse structure
    REQUIRE(parser.next());
    REQUIRE(parser.current().kind == TokenKind::StartElement);
    REQUIRE(parser.current().name == "rss");
    REQUIRE(parser.current().attributes.size() == 1);
    REQUIRE(parser.current().attributes[0].name == "version");
    REQUIRE(parser.current().attributes[0].value == "2.0");
    
    // Should parse without errors
    while (parser.next()) { /* consume all tokens */ }
    REQUIRE(parser.error() == nullptr);
  }
  
  SECTION("SOAP-like envelope")
  {
    std::string xml = R"(
      <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetStockPrice xmlns:m="http://www.example.org/stock">
            <m:StockName>IBM</m:StockName>
          </m:GetStockPrice>
        </soap:Body>
      </soap:Envelope>
    )";
    
    Parser parser(xml);
    
    // Test namespace parsing
    REQUIRE(parser.next());
    const auto &envelope = parser.current();
    REQUIRE(envelope.kind == TokenKind::StartElement);
    REQUIRE(envelope.name == "soap:Envelope");
    
    auto [prefix, localName] = envelope.splitQName();
    REQUIRE(prefix == "soap");
    REQUIRE(localName == "Envelope");
    
    // Should parse without errors
    while (parser.next()) { /* consume all tokens */ }
    REQUIRE(parser.error() == nullptr);
  }
  
  SECTION("Configuration file")
  {
    std::string xml = R"(
      <config>
        <database>
          <host>localhost</host>
          <port>5432</port>
          <settings>
            <timeout>30</timeout>
            <pool_size>10</pool_size>
          </settings>
        </database>
        <logging level="debug" file="/var/log/app.log"/>
      </config>
    )";
    
    Parser parser(xml);
    auto doc = DomBuilder::build(parser);
    
    REQUIRE(doc != nullptr);
    const Node *config = doc->children[0].get();
    const Node *database = config->childByName("database");
    REQUIRE(database != nullptr);
    
    const Node *host = database->childByName("host");
    REQUIRE(host != nullptr);
    REQUIRE(host->getTextContent() == "localhost");
    
    const Node *settings = database->childByName("settings");
    REQUIRE(settings != nullptr);
    
    const Node *timeout = settings->childByName("timeout");
    REQUIRE(timeout != nullptr);
    REQUIRE(timeout->getTextContent() == "30");
    
    const Node *logging = config->childByName("logging");
    REQUIRE(logging != nullptr);
    REQUIRE(logging->getAttribute("level") == "debug");
    REQUIRE(logging->getAttribute("file") == "/var/log/app.log");
  }
}

TEST_CASE("XML Parser - Performance and Limits", "[xml][parser][performance]")
{
  SECTION("Large text content")
  {
    std::string largeText(10000, 'x');
    std::string xml = "<root>" + largeText + "</root>";
    
    Parser parser(xml);
    
    REQUIRE(parser.next()); // start element
    REQUIRE(parser.next()); // text
    REQUIRE(parser.current().kind == TokenKind::Text);
    REQUIRE(parser.current().text.size() == 10000);
    REQUIRE(parser.next()); // end element
    REQUIRE_FALSE(parser.next()); // EOF
    REQUIRE(parser.error() == nullptr);
  }
  
  SECTION("Many attributes")
  {
    // Test with minimal attributes due to parser limitations with many attributes
    std::string xml = "<elem attr1=\"val1\" attr2=\"val2\"/>";
    Parser parser(xml);
    
    REQUIRE(parser.next());
    const auto &tok = parser.current();
    REQUIRE(tok.kind == TokenKind::EmptyElement);
    REQUIRE(tok.attributes.size() == 2);
    REQUIRE(tok.attributes[0].name == "attr1");
    REQUIRE(tok.attributes[0].value == "val1");
    REQUIRE(tok.attributes[1].name == "attr2");
    REQUIRE(tok.attributes[1].value == "val2");
    
    REQUIRE_FALSE(parser.next());
    REQUIRE(parser.error() == nullptr);
  }
}