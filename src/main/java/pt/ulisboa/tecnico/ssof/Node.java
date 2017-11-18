package pt.ulisboa.tecnico.ssof;

import org.apache.commons.lang.StringUtils;

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

    public NodeType getType() {
        return type;
    }

    public int getDepth(){
        if(parentNode == null)
            return 0;
        else return 1 + parentNode.getDepth();
    }

    @Override
    public String toString() {
        return "Node{" +
                "name='" + name + '\'' +
                ", childNodes=" + childNodes +
                ", type=" + type +
                "}\n";
    }

    public void print(){
        print(0);
    }

    public void print(int i){
        if(isLeaf())
            System.out.println(StringUtils.repeat("\t", i) + "[NODE] name='"+name+"', type='"+type+"', children=[]");
        else {
            System.out.println(StringUtils.repeat("\t", i) + "[NODE] name='" + name + "', type='" + type + "', children=[");
            for (Node node : childNodes) {
                node.print(i + 1);
            }
            System.out.println(StringUtils.repeat("\t", i) + "]");
        }
    }
}
