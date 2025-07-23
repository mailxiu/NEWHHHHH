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
@TableName("carousel")
/*    */ public class Carousel implements Serializable {
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String merchant;
    /*    */   private Integer sort;
    /*    */   private String imageUri;

    /*    */
    /* 13 */
    public void setId(Integer id) {
        this.id = id;
    }

    private String event;
    private String respond;
    private Integer state;
    @TableField(fill = FieldFill.INSERT)
    private Date createTime;
    private static final long serialVersionUID = 1L;

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public void setImageUri(String imageUri) {
        this.imageUri = imageUri;
    }

    public void setEvent(String event) {
        this.event = event;
    }

    public void setRespond(String respond) {
        this.respond = respond;
    }

    public void setState(Integer state) {
        this.state = state;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Carousel)) return false;
        com.bss.entity.Carousel other = (com.bss.entity.Carousel) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$imageUri = getImageUri(), other$imageUri = other.getImageUri();
        if (!Objects.equals(this$imageUri, other$imageUri)) return false;
        Object this$event = getEvent(), other$event = other.getEvent();
        if (!Objects.equals(this$event, other$event)) return false;
        Object this$respond = getRespond(), other$respond = other.getRespond();
        if (!Objects.equals(this$respond, other$respond)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Carousel;
    }



    public String toString() {
        return "Carousel(id=" + getId() + ", merchant=" + getMerchant() + ", sort=" + getSort() + ", imageUri=" + getImageUri() + ", event=" + getEvent() + ", respond=" + getRespond() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    public String getMerchant() {
        /* 18 */
        return this.merchant;
        /*    */
    }

    public Integer getSort() {
        /* 20 */
        return this.sort;
        /*    */
    }

    public String getImageUri() {
        /* 22 */
        return this.imageUri;
        /*    */
    }

    public String getEvent() {
        /* 24 */
        return this.event;
        /*    */
    }

    public String getRespond() {
        /* 26 */
        return this.respond;
        /*    */
    }

    public Integer getState() {
        /* 28 */
        return this.state;
        /*    */
    }

    /*    */
    public Date getCreateTime() {
        /* 31 */
        return this.createTime;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Carousel.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */