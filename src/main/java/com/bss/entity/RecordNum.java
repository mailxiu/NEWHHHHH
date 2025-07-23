/*    */
package com.bss.entity;
/*    */
/*    */

import java.util.Date;
import java.util.Objects;

/*    */
/*    */ public class RecordNum
        /*    */ {
    /*    */   private Integer id;
    /*    */   private String name;
    /*    */   private String image;
    /*    */   private String code;
    /*    */   private String createTime;
    /*    */   private Date earliestUpdateTime;
    /*    */   private Integer num;

    public RecordNum(Integer id, String name, String image, String code, String createTime, Date earliestUpdateTime, Integer num) {
        /* 17 */
        this.id = id;
        this.name = name;
        this.image = image;
        this.code = code;
        this.createTime = createTime;
        this.earliestUpdateTime = earliestUpdateTime;
        this.num = num;
        /*    */
    }

    /*    */
    public RecordNum() {
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.RecordNum)) return false;
        com.bss.entity.RecordNum other = (com.bss.entity.RecordNum) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$image = getImage(), other$image = other.getImage();
        if (!Objects.equals(this$image, other$image)) return false;
        Object this$code = getCode(), other$code = other.getCode();
        if (!Objects.equals(this$code, other$code)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        if (!Objects.equals(this$createTime, other$createTime))
            return false;
        Object this$earliestUpdateTime = getEarliestUpdateTime(), other$earliestUpdateTime = other.getEarliestUpdateTime();
        if (!Objects.equals(this$earliestUpdateTime, other$earliestUpdateTime))
            return false;
        Object this$num = getNum(), other$num = other.getNum();
        return !(!Objects.equals(this$num, other$num));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.RecordNum;
    }


    public String toString() {
        return "RecordNum(id=" + getId() + ", name=" + getName() + ", image=" + getImage() + ", code=" + getCode() + ", createTime=" + getCreateTime() + ", earliestUpdateTime=" + getEarliestUpdateTime() + ", num=" + getNum() + ")";
    }

    /*    */
    public Integer getId() {
        /* 21 */
        return this.id;
        /*    */
    }

    /*    */
    /*    */
    public void setId(Integer id) {
        /* 16 */
        this.id = id;
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

    public String getCode() {
        /* 27 */
        return this.code;
        /*    */
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getCreateTime() {
        /* 29 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public Date getEarliestUpdateTime() {
        /* 31 */
        return this.earliestUpdateTime;
        /*    */
    }

    public void setEarliestUpdateTime(Date earliestUpdateTime) {
        this.earliestUpdateTime = earliestUpdateTime;
    }

    public Integer getNum() {
        /* 33 */
        return this.num;
        /*    */
    }

    public void setNum(Integer num) {
        this.num = num;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\RecordNum.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */