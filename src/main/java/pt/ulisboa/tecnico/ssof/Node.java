package pt.ulisboa.tecnico.ssof;

import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import java.util.UUID;

public class Node {
    private final UUID uuid; //Node id to ease equals comparison
    private String name;
    private Node parentNode;
    private List<Node> childNodes;
    private NodeType type;
    private List<VulnPattern> vulns;
    private NodeStatus status;
    private Node root;
    HashMap<String, NodeStatus> varStatus;
    HashMap<String, Node> rescueNode;

    enum NodeStatus {
        OK, TOXIC, ATTACK
    }

    public Node(NodeType type){
        childNodes = new ArrayList<>();
        this.type = type;
        vulns = new ArrayList<>();
        status = NodeStatus.OK;
        parentNode = null;
        uuid = UUID.randomUUID();
        varStatus = new HashMap<>();
        rescueNode = new HashMap<>();
    }

    public Node(NodeType type, Node root){
        childNodes = new ArrayList<>();
        this.type = type;
        status = NodeStatus.OK;
        parentNode = null;
        uuid = UUID.randomUUID();
        this.root = root;
    }

    public Node(String name, NodeType type, Node root){
        this(type, root);
        this.name = name;
    }

    public void appendChild(Node node){
        node.setParentNode(this);
        childNodes.add(node);
    }

    public void setRoot(Node root){
        this.root = root;
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

    public String getVulns() {
        if(root.vulns.size() == 1)
            return root.vulns.get(0).getName();

        String name = root.vulns.get(0).getName();
        for(int i = 1; i<root.vulns.size(); i++)
            name += ", " + root.vulns.get(i).getName();

        return name;
    }

    public List<Node> getSensitiveNodes(List<VulnPattern> patterns){
        List<Node> nodes = new ArrayList<>();
        if(this.type.equals(NodeType.FUNCALL)) {
            for (VulnPattern pattern : patterns) {
                if(pattern.getSensitiveSinks().contains(name)){ //O nó atual é uma chamada a nó sensível
                    if(!nodes.contains(this))
                        nodes.add(this);
                    root.addVuln(pattern);
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

    public void addVuln(VulnPattern vp){
        if(!vulns.contains(vp))
            vulns.add(vp);
    }

    public NodeStatus getStatus(){
        return status;
    }

    public void processIntegrityCheck(){
        if(!isLeaf()) {
            for (Node child : childNodes) {
                child.processIntegrityCheck();
            }
        }

        for(VulnPattern vp: root.vulns){
            if(type.equals(NodeType.VARIABLE)){
                if(vp.getEntryPoints().contains(name)) { //entry point found
                    status = NodeStatus.TOXIC;
                    root.varStatus.put(getName(), status);
                }
                else if(root.varStatus.containsKey(name)){
                        status = root.varStatus.get(name);
                }
            }
            else if(type.equals(NodeType.ASSIGN)) {
                Node left = childNodes.get(0);
                Node right = childNodes.get(1);

                if(right.getType().equals(NodeType.FUNCALL)){
                    if(vp.getSanitizeFunctions().contains(right.getName())) { //sanitize found
                        status = NodeStatus.OK;
                        root.varStatus.put(left.getName(), status);
                        root.rescueNode.put(left.getName(), right);
                    }
                }
                else
                    status = andNodeStatus(right);
                left.setStatus(status);
                root.varStatus.put(left.getName(), status);
            }
            else if(type.equals(NodeType.ENCAPSED)){
                status = andNodeStatus(childNodes.toArray(new Node[childNodes.size()]));
            }
        }
    }

    public void setStatus(NodeStatus ns){
        status = ns;
    }

    public String getVarName(){
        for(Node n: childNodes){
            if(root.rescueNode.containsKey(n.getName()))
                return n.getName();
        }
        return null;
    }

    private NodeStatus andNodeStatus(Node... nodes){
        for(Node n: nodes){
            if(n.getStatus().equals(NodeStatus.TOXIC))
                return NodeStatus.TOXIC;
        }
        return NodeStatus.OK;
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

    public boolean isVulnerable(){
        return andNodeStatus(childNodes.toArray(new Node[childNodes.size()])) != NodeStatus.OK;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Node node = (Node) o;

        return this.uuid.equals(node.uuid);
    }
}
