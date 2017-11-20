package pt.ulisboa.tecnico.ssof;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Analyser {
    private static final String PATTERNS_PATH = "patterns/all.txt";
    private static boolean PRINT_DEBUG_INFO = false;

    private File jsonSource;
    private List<VulnPattern> vulnPatterns;
    private JsonObject astJSON;
    private Node tree;

    public Analyser(File jsonSource){
        this.jsonSource = jsonSource;
        this.vulnPatterns = new ArrayList<>();
    }

    public void run() throws IOException {
        loadPatterns();
        buildTreeFromJSON();
        findVulnerabilities();
    }

    public void toggleDebugInfo(){
        PRINT_DEBUG_INFO = !PRINT_DEBUG_INFO;
    }

    private void loadPatterns() throws IOException {
        if(PRINT_DEBUG_INFO)
            System.out.println("\nStarting loading patterns");

        List<String> fileLines = readFile(PATTERNS_PATH);
        for(int i=0; i < fileLines.size(); i=i+5){
            VulnPattern v = new VulnPattern(
                    fileLines.get(i), //vuln name
                    Arrays.asList(fileLines.get(i+1).split(",")), //entry points
                    Arrays.asList(fileLines.get(i+2).split(",")), //sanitization functions
                    Arrays.asList(fileLines.get(i+3).split(",")) //sensitive sinks
            );
            vulnPatterns.add(v);

            if(PRINT_DEBUG_INFO) {
                System.out.println(v + " loaded");
            }
        }
        if(PRINT_DEBUG_INFO)
            System.out.println("Finished loading patterns");
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
        if(PRINT_DEBUG_INFO)
            System.out.println("\nStarted loading tree");

        astJSON = new JsonParser().parse(new FileReader(jsonSource)).getAsJsonObject();
        tree = new Node(NodeType.PROGRAM);
        tree.setRoot(tree);

        if(PRINT_DEBUG_INFO)
            System.out.println(StringUtils.repeat("\t", tree.getDepth()) + tree.getType());

        for(JsonElement child: astJSON.get("children").getAsJsonArray()){
            processNode(tree, child.getAsJsonObject());
        }

        if(PRINT_DEBUG_INFO)
            System.out.println("Finished loading tree");
    }

    private void processNode(Node parent, JsonObject ast){
        Node node;
        switch (ast.get("kind").getAsString()){
            case "offsetlookup":
                node = new Node(ast.get("what").getAsJsonObject().get("name").getAsString(), NodeType.VARIABLE, tree);
                break;
            case "variable":
                node = new Node(ast.get("name").getAsString(), NodeType.VARIABLE, tree);
                break;
            case "call":
                node = new Node(ast.get("what").getAsJsonObject().get("name").getAsString(), NodeType.FUNCALL, tree);
                break;
            case "if":
                node = new Node(NodeType.IF, tree);
                break;
            case "block":
                node = new Node(NodeType.BLOCK, tree);
                break;
            case "while":
                node = new Node(NodeType.WHILE, tree);
                break;
            case "inline":
                node = new Node(NodeType.INLINE, tree);
                break;
            case "echo":
                node = new Node("echo", NodeType.FUNCALL, tree);
                break;
            case "encapsed":
                node = new Node(NodeType.ENCAPSED, tree);
                break;
            case "assign":
                node = new Node(NodeType.ASSIGN, tree);
                break;
            case "bin":
                switch(ast.get("type").getAsString()){
                    case ".":
                        node = new Node(NodeType.ENCAPSED, tree);
                        break;
                    default:
                        node = new Node(NodeType.COMPARISON, tree);
                        break;
                }
                break;
            case "string":
                node = new Node(NodeType.STRING, tree);
                break;
            case "number":
                node = new Node(NodeType.NUMBER, tree);
                break;
            default:
                node = new Node(NodeType.UNKNOWN, tree);
                break;
        }

        parent.appendChild(node);

        if(PRINT_DEBUG_INFO)
            System.out.println(StringUtils.repeat("\t", node.getDepth()) + node.getType() + ">" + node.getName());

        if(ast.has("left") && ast.has("right")) {
            processNode(node, ast.get("left").getAsJsonObject());
            processNode(node, ast.get("right").getAsJsonObject());
        }

        if(ast.has("arguments")){
            for(JsonElement argument: ast.get("arguments").getAsJsonArray())
                processNode(node, argument.getAsJsonObject());
        }

        if(ast.get("kind").getAsString().equals("encapsed")){
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

        if(ast.has("body")  && !ast.get("body").isJsonNull()){
            processNode(node, ast.get("body").getAsJsonObject());
        }

        if(ast.has("alternate") && !ast.get("alternate").isJsonNull()){
            processNode(node, ast.get("alternate").getAsJsonObject());
        }
    }

    private void findVulnerabilities(){
        if(PRINT_DEBUG_INFO)
            System.out.println("\nStarting finding vulnPatterns");

        List<Node> sensitiveSinks = tree.getSensitiveNodes(vulnPatterns);
        List<Node> vulns = new ArrayList<>();

        tree.processIntegrityCheck();

        for(Node n: sensitiveSinks){
            if(n.isVulnerable()){
                vulns.add(n);
            }
        }

        if(PRINT_DEBUG_INFO){
            System.out.println(tree.varStatus);
            System.out.println(tree.rescueNode);
        }

        for(Node n: sensitiveSinks){
            if(vulns.contains(n))
                System.out.println("This program is vulnerable in function call " + n.getName());
            else
                System.out.println("This program was potentially vulnerable in function call " + n.getName() +
                        ", but " + tree.rescueNode.get(n.getVarName()).getName() + " validated the value");
        }



        if(PRINT_DEBUG_INFO)
            System.out.println("Finished finding vulnPatterns");
    }
}
