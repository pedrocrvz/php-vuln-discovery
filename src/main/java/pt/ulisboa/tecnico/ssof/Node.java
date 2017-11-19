package pt.ulisboa.tecnico.ssof;

import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.List;

import java.util.UUID;

public class Node {
    private final UUID uuid = UUID.randomUUID(); //Node id ti ease equals comparison
    private String name;
    private Node parentNode = null;
    private List<Node> childNodes;
    private NodeType type;
    private List<VulnPattern> vulns;

    public Node(NodeType type){
        childNodes = new ArrayList<>();
        this.type = type;
        vulns = new ArrayList<>();
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

    public List<Node> getChildNodes() {
        return childNodes;
    }

    public UUID getUuid() {
        return uuid;
    }

    public String getName() {
        return name;
    }

    public Node getParentNode() {
        return parentNode;
    }

    public List<VulnPattern> getVulns() {
        return vulns;
    }

    public List<Node> getSensitiveNodes(List<VulnPattern> patterns){
        List<Node> nodes = new ArrayList<>();
        if(this.type.equals(NodeType.FUNCALL)) {
            for (VulnPattern pattern : patterns) {
                if(pattern.getSensitiveSinks().contains(name)){ //O nó atual é uma chamada a nó sensível
                    if(!nodes.contains(this))
                        nodes.add(this);
                    this.vulns.add(pattern);
                }
            }
        }
        else{
            if(!isLeaf()){
                for(Node child: getChildNodes()){
                    nodes.addAll(child.getSensitiveNodes(patterns));
                }
            }
        }
        return nodes;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Node node = (Node) o;

        return this.uuid.equals(node.uuid);
    }
}
