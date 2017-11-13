package pt.ulisboa.tecnico.ssof;

import java.util.ArrayList;
import java.util.List;

public class Node {
    private String name;
    private Node parentNode = null;
    private List<Node> childNodes;
    private NodeType type;

    public Node(NodeType type){
        childNodes = new ArrayList<>();
        this.type = type;
    }

    public Node(String name, NodeType type){
        this(type);
        this.name = name;
    }

    public void appendChild(Node node){
        node.setParentNode(this);
        childNodes.add(node);
    }

    public void setParentNode(Node node){
        this.parentNode = node;
    }
}
