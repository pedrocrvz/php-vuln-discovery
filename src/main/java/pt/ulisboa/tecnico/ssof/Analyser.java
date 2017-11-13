package pt.ulisboa.tecnico.ssof;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

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

        System.out.println(tree);
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
                node = new Node(ast.get("what").getAsJsonObject().get("name").getAsString(), NodeType.FUNCTION);
                break;
            case "encapsed":
                node = new Node(NodeType.ENCAPSED);
                break;
            case "assign":
                node = new Node(NodeType.ASSIGN);
                break;
            case "bin":
                node = new Node(NodeType.CONCAT);
                break;
            case "string":
                node = new Node(NodeType.STRING);
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
            for(JsonElement argument: ast.get("arguments").getAsJsonArray()){
                processNode(node, argument.getAsJsonObject());
            }
        }
        else if(ast.get("kind").getAsString().equals("encapsed")){
            for(JsonElement element: ast.get("value").getAsJsonArray()){
                processNode(node, element.getAsJsonObject());
            }
        }
    }

    private void findVulnerabilities(){
    }
}
