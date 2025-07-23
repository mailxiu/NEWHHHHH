/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.*;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("settlement")
/*    */ public class Settlement implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String sid;
    /*    */   private String uid;
    /*    */   private String type;
    private Double total;
    private String notes;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Settlement)) return false;
        com.bss.entity.Settlement other = (com.bss.entity.Settlement) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$sid = getSid(), other$sid = other.getSid();
        if (!Objects.equals(this$sid, other$sid)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if (!Objects.equals(this$uid, other$uid)) return false;
        Object this$type = getType(), other$type = other.getType();
        if (!Objects.equals(this$type, other$type)) return false;
        Object this$total = getTotal(), other$total = other.getTotal();
        if (!Objects.equals(this$total, other$total)) return false;
        Object this$notes = getNotes(), other$notes = other.getNotes();
        if (!Objects.equals(this$notes, other$notes)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Settlement;
    }


    public String toString() {
        return "Settlement(id=" + getId() + ", sid=" + getSid() + ", uid=" + getUid() + ", type=" + getType() + ", total=" + getTotal() + ", notes=" + getNotes() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 17 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getSid() {
        /* 19 */
        return this.sid;
        /*    */
    }

    public void setSid(String sid) {
        this.sid = sid;
    }

    public String getUid() {
        /* 21 */
        return this.uid;
        /*    */
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getType() {
        /* 23 */
        return this.type;
        /*    */
    }

    public void setType(String type) {
        this.type = type;
    }

    public Double getTotal() {
        /* 25 */
        return this.total;
        /*    */
    }

    public void setTotal(Double total) {
        this.total = total;
    }

    public String getNotes() {
        /* 27 */
        return this.notes;
        /*    */
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    /*    */
    public Date getCreateTime() {
        /* 30 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Settlement.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */