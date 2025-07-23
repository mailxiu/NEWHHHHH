/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("complaint")
/*    */ public class Complaint {
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String complaintNumber;
    /*    */   private String complaintUid;
    /*    */   private String complaintRefer;
    /*    */   private String content;

    /*    */
    /* 12 */
    public void setId(Integer id) {
        this.id = id;
    }

    private String phone;
    private String reply;
    private String images;
    private Integer state;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date updateTime;
    @TableField(fill = FieldFill.INSERT)
    private Date createTime;

    public void setComplaintNumber(String complaintNumber) {
        this.complaintNumber = complaintNumber;
    }

    public void setComplaintUid(String complaintUid) {
        this.complaintUid = complaintUid;
    }

    public void setComplaintRefer(String complaintRefer) {
        this.complaintRefer = complaintRefer;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public void setReply(String reply) {
        this.reply = reply;
    }

    public void setImages(String images) {
        this.images = images;
    }

    public void setState(Integer state) {
        this.state = state;
    }

    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Complaint)) return false;
        com.bss.entity.Complaint other = (com.bss.entity.Complaint) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$complaintNumber = getComplaintNumber(), other$complaintNumber = other.getComplaintNumber();
        if (!Objects.equals(this$complaintNumber, other$complaintNumber))
            return false;
        Object this$complaintUid = getComplaintUid(), other$complaintUid = other.getComplaintUid();
        if (!Objects.equals(this$complaintUid, other$complaintUid))
            return false;
        Object this$complaintRefer = getComplaintRefer(), other$complaintRefer = other.getComplaintRefer();
        if (!Objects.equals(this$complaintRefer, other$complaintRefer))
            return false;
        Object this$content = getContent(), other$content = other.getContent();
        if (!Objects.equals(this$content, other$content)) return false;
        Object this$phone = getPhone(), other$phone = other.getPhone();
        if (!Objects.equals(this$phone, other$phone)) return false;
        Object this$reply = getReply(), other$reply = other.getReply();
        if (!Objects.equals(this$reply, other$reply)) return false;
        Object this$images = getImages(), other$images = other.getImages();
        if (!Objects.equals(this$images, other$images)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$updateTime = getUpdateTime(), other$updateTime = other.getUpdateTime();
        if (!Objects.equals(this$updateTime, other$updateTime))
            return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Complaint;
    }


    public String toString() {
        return "Complaint(id=" + getId() + ", complaintNumber=" + getComplaintNumber() + ", complaintUid=" + getComplaintUid() + ", complaintRefer=" + getComplaintRefer() + ", content=" + getContent() + ", phone=" + getPhone() + ", reply=" + getReply() + ", images=" + getImages() + ", state=" + getState() + ", updateTime=" + getUpdateTime() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    public String getComplaintNumber() {
        /* 17 */
        return this.complaintNumber;
        /*    */
    }

    public String getComplaintUid() {
        /* 19 */
        return this.complaintUid;
        /*    */
    }

    public String getComplaintRefer() {
        /* 21 */
        return this.complaintRefer;
        /*    */
    }

    public String getContent() {
        /* 23 */
        return this.content;
        /*    */
    }

    public String getPhone() {
        /* 25 */
        return this.phone;
        /*    */
    }

    public String getReply() {
        /* 27 */
        return this.reply;
        /*    */
    }

    public String getImages() {
        /* 29 */
        return this.images;
        /*    */
    }

    public Integer getState() {
        /* 31 */
        return this.state;
        /*    */
    }

    /*    */
    public Date getUpdateTime() {
        /* 34 */
        return this.updateTime;
        /*    */
    }

    /*    */
    public Date getCreateTime() {
        /* 37 */
        return this.createTime;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Complaint.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */