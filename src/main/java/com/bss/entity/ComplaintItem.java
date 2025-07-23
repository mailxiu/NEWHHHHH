/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("complaint_item")
/*    */ public class ComplaintItem {
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String complaintNumber;
    /*    */   private String sessionType;
    private String content;
    private String images;
    @TableField(fill = FieldFill.INSERT)
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ComplaintItem)) return false;
        com.bss.entity.ComplaintItem other = (com.bss.entity.ComplaintItem) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$complaintNumber = getComplaintNumber(), other$complaintNumber = other.getComplaintNumber();
        if (!Objects.equals(this$complaintNumber, other$complaintNumber))
            return false;
        Object this$sessionType = getSessionType(), other$sessionType = other.getSessionType();
        if (!Objects.equals(this$sessionType, other$sessionType))
            return false;
        Object this$content = getContent(), other$content = other.getContent();
        if (!Objects.equals(this$content, other$content)) return false;
        Object this$images = getImages(), other$images = other.getImages();
        if (!Objects.equals(this$images, other$images)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return Objects.equals(this$createTime, other$createTime);
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ComplaintItem;
    }


    public String toString() {
        return "ComplaintItem(id=" + getId() + ", complaintNumber=" + getComplaintNumber() + ", sessionType=" + getSessionType() + ", content=" + getContent() + ", images=" + getImages() + ", createTime=" + getCreateTime() + ")";
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

    public String getComplaintNumber() {
        /* 17 */
        return this.complaintNumber;
        /*    */
    }

    public void setComplaintNumber(String complaintNumber) {
        this.complaintNumber = complaintNumber;
    }

    public String getSessionType() {
        /* 19 */
        return this.sessionType;
        /*    */
    }

    public void setSessionType(String sessionType) {
        this.sessionType = sessionType;
    }

    public String getContent() {
        /* 21 */
        return this.content;
        /*    */
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getImages() {
        /* 23 */
        return this.images;
        /*    */
    }

    public void setImages(String images) {
        this.images = images;
    }

    /*    */
    public Date getCreateTime() {
        /* 26 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ComplaintItem.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */