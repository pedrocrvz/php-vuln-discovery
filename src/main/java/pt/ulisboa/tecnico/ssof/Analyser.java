package pt.ulisboa.tecnico.ssof;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Analyser {
    private static final String PATTERNS_PATH = "patterns/all.txt";

    private File jsonSource;
    private List<Vulnerability> vulnerabilities;
    private JsonObject astJSON;
    private Node tree;

    public Analyser(File jsonSource){
        this.jsonSource = jsonSource;
        this.vulnerabilities = new ArrayList<>();
    }

    public void run() throws IOException {
        loadPatterns();
        buildTreeFromJSON();
        findVulnerabilities();
    }

    private void loadPatterns() throws IOException {
        List<String> fileLines = readFile(PATTERNS_PATH);
        for(int i=0; i < fileLines.size(); i=i+5){
            vulnerabilities.add(new Vulnerability(
                    fileLines.get(i), //vuln name
                    Arrays.asList(fileLines.get(i+1).split(",")), //entry points
                    Arrays.asList(fileLines.get(i+2).split(",")), //sanitization functions
                    Arrays.asList(fileLines.get(i+3).split(",")) //sensitive sinks
            ));
        }
    }

    private List<String> readFile(String filePath) throws IOException {
        ArrayList<String> lines = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(filePath));
        String sCurrentLine;

        while ((sCurrentLine = br.readLine()) != null) {
            lines.add(sCurrentLine);
        }

        br.close();

        return lines;
    }

    private void buildTreeFromJSON() throws FileNotFoundException {
        astJSON = new JsonParser().parse(new FileReader(jsonSource)).getAsJsonObject();
        tree = new Node(NodeType.PROGRAM);
        for(JsonElement child: astJSON.get("children").getAsJsonArray()){
            processNode(tree, child.getAsJsonObject());
        }

        tree.print();
    }

    private void processNode(Node parent, JsonObject ast){
        Node node;
        switch (ast.get("kind").getAsString()){
            case "offsetlookup":
                node = new Node(ast.get("what").getAsJsonObject().get("name").getAsString(), NodeType.VARIABLE);
                break;
            case "variable":
                node = new Node(ast.get("name").getAsString(), NodeType.VARIABLE);
                break;
            case "call":
                node = new Node(ast.get("what").getAsJsonObject().get("name").getAsString(), NodeType.FUNCALL);
                break;
            case "if":
                node = new Node(NodeType.IF);
                break;
            case "block":
                node = new Node(NodeType.BLOCK);
                break;
            case "while":
                node = new Node(NodeType.WHILE);
                break;
            case "inline":
                node = new Node(NodeType.INLINE);
                break;
            case "echo":
                node = new Node(NodeType.ECHO);
                break;
            case "encapsed":
                node = new Node(NodeType.ENCAPSED);
                break;
            case "assign":
                node = new Node(NodeType.ASSIGN);
                break;
            case "bin":
                switch(ast.get("type").getAsString()){
                    case ".":
                        node = new Node(NodeType.CONCAT);
                        break;
                    default:
                        node = new Node(NodeType.COMPARISON);
                        break;
                }
                break;
            case "string":
                node = new Node(NodeType.STRING);
                break;
            case "number":
                node = new Node(NodeType.NUMBER);
                break;
            default:
                node = new Node(NodeType.UNKNOWN);
                break;
        }

        parent.appendChild(node);

        if(ast.has("left") && ast.has("right")) {
            processNode(node, ast.get("left").getAsJsonObject());
            processNode(node, ast.get("right").getAsJsonObject());
        }
        else if(ast.has("arguments")){
            for(JsonElement argument: ast.get("arguments").getAsJsonArray())
                processNode(node, argument.getAsJsonObject());
        }
        else if(ast.get("kind").getAsString().equals("encapsed")){
            for(JsonElement element: ast.get("value").getAsJsonArray())
                processNode(node, element.getAsJsonObject());
        }

        if(ast.has("children")){
            for(JsonElement child: ast.get("children").getAsJsonArray())
                processNode(node, child.getAsJsonObject());
        }

        if(ast.has("test")){
            processNode(node, ast.get("test").getAsJsonObject());
        }

        if(ast.has("body")){
            processNode(node, ast.get("body").getAsJsonObject());
        }

        if(ast.has("alternate")){
            processNode(node, ast.get("alternate").getAsJsonObject());
        }

    }

    private void findVulnerabilities(){
    }
}
