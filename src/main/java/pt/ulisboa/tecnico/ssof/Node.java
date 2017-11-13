package pt.ulisboa.tecnico.ssof;

import java.util.ArrayList;
import java.util.List;

public class Node {
    String name;
    Node parentNode = null;
    List<Node> childNodes;
    NodeType type;

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

    public boolean isLeaf(){
        return childNodes.size() == 0;
    }

    @Override
    public String toString() {
        return "Node{" +
                "name='" + name + '\'' +
                ", childNodes=" + childNodes +
                ", type=" + type +
                "}\n";
    }
}
