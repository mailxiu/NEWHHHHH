/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.util.Arrays;
import java.util.Objects;

/*    */
/*    */
@TableName("complaint")
/*    */ public class ComplaintVo {
    /*    */   private String complaintNumber;
    /*    */   private String complaintUid;
    /*    */   private String complaintRefer;
    private String content;
    private String phone;
    private String reply;
    private String[] images;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ComplaintVo)) return false;
        com.bss.entity.ComplaintVo other = (com.bss.entity.ComplaintVo) o;
        if (!other.canEqual(this)) return false;
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
        return Objects.equals(this$reply, other$reply) && (Arrays.deepEquals(getImages(), other.getImages()));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ComplaintVo;
    }


    public String toString() {
        return "ComplaintVo(complaintNumber=" + getComplaintNumber() + ", complaintUid=" + getComplaintUid() + ", complaintRefer=" + getComplaintRefer() + ", content=" + getContent() + ", phone=" + getPhone() + ", reply=" + getReply() + ", images=" + Arrays.deepToString(getImages()) + ")";
    }

    /*    */
    /*    */
    public String getComplaintNumber() {
        /* 15 */
        return this.complaintNumber;
        /*    */
    }

    /*    */
    /* 12 */
    public void setComplaintNumber(String complaintNumber) {
        this.complaintNumber = complaintNumber;
    }

    public String getComplaintUid() {
        /* 17 */
        return this.complaintUid;
        /*    */
    }

    public void setComplaintUid(String complaintUid) {
        this.complaintUid = complaintUid;
    }

    public String getComplaintRefer() {
        /* 19 */
        return this.complaintRefer;
        /*    */
    }

    public void setComplaintRefer(String complaintRefer) {
        this.complaintRefer = complaintRefer;
    }

    public String getContent() {
        /* 21 */
        return this.content;
        /*    */
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getPhone() {
        /* 23 */
        return this.phone;
        /*    */
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getReply() {
        /* 25 */
        return this.reply;
        /*    */
    }

    public void setReply(String reply) {
        this.reply = reply;
    }

    public String[] getImages() {
        /* 27 */
        return this.images;
        /*    */
    }

    public void setImages(String[] images) {
        this.images = images;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ComplaintVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */