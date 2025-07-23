/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.*;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/*    */
@TableName("project")
/*    */ public class Project implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String merchant;
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
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Project)) return false;
        com.bss.entity.Project other = (com.bss.entity.Project) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
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
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Project;
    }


    public String toString() {
        return "Project(id=" + getId() + ", merchant=" + getMerchant() + ", cid=" + getCid() + ", sort=" + getSort() + ", barCode=" + getBarCode() + ", name=" + getName() + ", image=" + getImage() + ", points=" + getPoints() + ", pattern=" + getPattern() + ", checking=" + getChecking() + ", mixed=" + getMixed() + ", remarks=" + getRemarks() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    /*    */
    public Integer getId() {
        /* 17 */
        return this.id;
        /*    */
    }

    /*    */
    /* 13 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getMerchant() {
        /* 19 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public String getCid() {
        /* 21 */
        return this.cid;
        /*    */
    }

    public void setCid(String cid) {
        this.cid = cid;
    }

    public Integer getSort() {
        /* 23 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public String getBarCode() {
        /* 25 */
        return this.barCode;
        /*    */
    }

    public void setBarCode(String barCode) {
        this.barCode = barCode;
    }

    public String getName() {
        /* 27 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImage() {
        /* 29 */
        return this.image;
        /*    */
    }

    public void setImage(String image) {
        this.image = image;
    }

    public Double getPoints() {
        /* 31 */
        return this.points;
        /*    */
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public String getPattern() {
        /* 33 */
        return this.pattern;
        /*    */
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public Boolean getChecking() {
        /* 35 */
        return this.checking;
        /*    */
    }

    public void setChecking(Boolean checking) {
        this.checking = checking;
    }

    public Boolean getMixed() {
        /* 37 */
        return this.mixed;
        /*    */
    }

    public void setMixed(Boolean mixed) {
        this.mixed = mixed;
    }

    public String getRemarks() {
        /* 39 */
        return this.remarks;
        /*    */
    }

    public void setRemarks(String remarks) {
        this.remarks = remarks;
    }

    public String getState() {
        /* 41 */
        return this.state;
        /*    */
    }

    public void setState(String state) {
        this.state = state;
    }

    /*    */
    public Date getCreateTime() {
        /* 44 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Project.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */