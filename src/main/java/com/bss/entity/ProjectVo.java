/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("project")
/*    */ public class ProjectVo implements Serializable {
    /*    */   private Integer id;
    /*    */   private String cid;
    /*    */   private Integer sort;
    /*    */   private String barCode;
    /*    */   private String name;
    /*    */   private String image;
    private Double points;
    private String pattern;
    private Boolean checking;
    private Boolean mixed;
    private String remarks;
    private String state;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ProjectVo)) return false;
        com.bss.entity.ProjectVo other = (com.bss.entity.ProjectVo) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$cid = getCid(), other$cid = other.getCid();
        if (!Objects.equals(this$cid, other$cid)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$barCode = getBarCode(), other$barCode = other.getBarCode();
        if (!Objects.equals(this$barCode, other$barCode)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$image = getImage(), other$image = other.getImage();
        if (!Objects.equals(this$image, other$image)) return false;
        Object this$points = getPoints(), other$points = other.getPoints();
        if (!Objects.equals(this$points, other$points)) return false;
        Object this$pattern = getPattern(), other$pattern = other.getPattern();
        if (!Objects.equals(this$pattern, other$pattern)) return false;
        Object this$checking = getChecking(), other$checking = other.getChecking();
        if (!Objects.equals(this$checking, other$checking)) return false;
        Object this$mixed = getMixed(), other$mixed = other.getMixed();
        if (!Objects.equals(this$mixed, other$mixed)) return false;
        Object this$remarks = getRemarks(), other$remarks = other.getRemarks();
        if (!Objects.equals(this$remarks, other$remarks)) return false;
        Object this$state = getState(), other$state = other.getState();
        return !(!Objects.equals(this$state, other$state));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ProjectVo;
    }


    public String toString() {
        return "ProjectVo(id=" + getId() + ", cid=" + getCid() + ", sort=" + getSort() + ", barCode=" + getBarCode() + ", name=" + getName() + ", image=" + getImage() + ", points=" + getPoints() + ", pattern=" + getPattern() + ", checking=" + getChecking() + ", mixed=" + getMixed() + ", remarks=" + getRemarks() + ", state=" + getState() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    /*    */
    /* 12 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getCid() {
        /* 17 */
        return this.cid;
        /*    */
    }

    public void setCid(String cid) {
        this.cid = cid;
    }

    public Integer getSort() {
        /* 19 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public String getBarCode() {
        /* 21 */
        return this.barCode;
        /*    */
    }

    public void setBarCode(String barCode) {
        this.barCode = barCode;
    }

    public String getName() {
        /* 23 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImage() {
        /* 25 */
        return this.image;
        /*    */
    }

    public void setImage(String image) {
        this.image = image;
    }

    public Double getPoints() {
        /* 27 */
        return this.points;
        /*    */
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public String getPattern() {
        /* 29 */
        return this.pattern;
        /*    */
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public Boolean getChecking() {
        /* 31 */
        return this.checking;
        /*    */
    }

    public void setChecking(Boolean checking) {
        this.checking = checking;
    }

    public Boolean getMixed() {
        /* 33 */
        return this.mixed;
        /*    */
    }

    public void setMixed(Boolean mixed) {
        this.mixed = mixed;
    }

    public String getRemarks() {
        /* 35 */
        return this.remarks;
        /*    */
    }

    public void setRemarks(String remarks) {
        this.remarks = remarks;
    }

    public String getState() {
        /* 37 */
        return this.state;
        /*    */
    }

    public void setState(String state) {
        this.state = state;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ProjectVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */