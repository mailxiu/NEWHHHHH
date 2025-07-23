/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("cigarette")
/*    */ public class Cigarette implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */   private Object id;
    /*    */   private String cid;
    /*    */   private String barCode;
    /*    */   private String name;
    /*    */   private String image;
    private Double points;
    private Integer checking;
    private Integer state;
    private String createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Cigarette)) return false;
        com.bss.entity.Cigarette other = (com.bss.entity.Cigarette) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$cid = getCid(), other$cid = other.getCid();
        if (!Objects.equals(this$cid, other$cid)) return false;
        Object this$barCode = getBarCode(), other$barCode = other.getBarCode();
        if (!Objects.equals(this$barCode, other$barCode)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$image = getImage(), other$image = other.getImage();
        if (!Objects.equals(this$image, other$image)) return false;
        Object this$points = getPoints(), other$points = other.getPoints();
        if (!Objects.equals(this$points, other$points)) return false;
        Object this$checking = getChecking(), other$checking = other.getChecking();
        if (!Objects.equals(this$checking, other$checking)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Cigarette;
    }


    public String toString() {
        return "Cigarette(id=" + getId() + ", cid=" + getCid() + ", barCode=" + getBarCode() + ", name=" + getName() + ", image=" + getImage() + ", points=" + getPoints() + ", checking=" + getChecking() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    public Object getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Object id) {
        this.id = id;
    }

    public String getCid() {
        /* 18 */
        return this.cid;
        /*    */
    }

    public void setCid(String cid) {
        this.cid = cid;
    }

    public String getBarCode() {
        /* 20 */
        return this.barCode;
        /*    */
    }

    public void setBarCode(String barCode) {
        this.barCode = barCode;
    }

    public String getName() {
        /* 22 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImage() {
        /* 24 */
        return this.image;
        /*    */
    }

    public void setImage(String image) {
        this.image = image;
    }

    public Double getPoints() {
        /* 26 */
        return this.points;
        /*    */
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public Integer getChecking() {
        /* 28 */
        return this.checking;
        /*    */
    }

    public void setChecking(Integer checking) {
        this.checking = checking;
    }

    public Integer getState() {
        /* 30 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }

    public String getCreateTime() {
        /* 32 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Cigarette.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */