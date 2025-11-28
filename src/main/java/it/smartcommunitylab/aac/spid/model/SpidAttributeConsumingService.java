package it.smartcommunitylab.aac.spid.model;

import java.io.Serializable;
import java.util.Set;

public class SpidAttributeConsumingService implements Serializable {
    
    private Integer index;
    private String name;
    private Set<SpidAttribute> attributes;

    public SpidAttributeConsumingService() {}

    public SpidAttributeConsumingService(Integer index, String name, Set<SpidAttribute> attributes){
        this.index = index;
        this.name = name;
        this.attributes = attributes;
    }

    public Integer getIndex() {
        return this.index;
    }

    public void setIndex(Integer index) {
        this.index = index;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name){
        this.name = name;
    }

    public Set<SpidAttribute> getAttributes() {
        return this.attributes;
    }

    public void setAttributes(Set<SpidAttribute> attributes) {
        this.attributes = attributes;
    }
}
