/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("message")
/*    */ public class Message {
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String uid;
    /*    */   private String title;

    /*    */
    /* 12 */
    public void setId(Integer id) {
        this.id = id;
    }

    private String info;
    private Integer state;
    @TableField(fill = FieldFill.INSERT)
    private Date createTime;

    public void setUid(String uid) {
        this.uid = uid;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public void setState(Integer state) {
        this.state = state;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Message)) return false;
        com.bss.entity.Message other = (com.bss.entity.Message) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if (!Objects.equals(this$uid, other$uid)) return false;
        Object this$title = getTitle(), other$title = other.getTitle();
        if (!Objects.equals(this$title, other$title)) return false;
        Object this$info = getInfo(), other$info = other.getInfo();
        if (!Objects.equals(this$info, other$info)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Message;
    }


    public String toString() {
        return "Message(id=" + getId() + ", uid=" + getUid() + ", title=" + getTitle() + ", info=" + getInfo() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    public String getUid() {
        /* 17 */
        return this.uid;
        /*    */
    }

    public String getTitle() {
        /* 19 */
        return this.title;
        /*    */
    }

    public String getInfo() {
        /* 21 */
        return this.info;
        /*    */
    }

    public Integer getState() {
        /* 23 */
        return this.state;
        /*    */
    }

    /*    */
    public Date getCreateTime() {
        /* 26 */
        return this.createTime;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Message.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */