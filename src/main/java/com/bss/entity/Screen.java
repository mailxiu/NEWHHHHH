/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

import java.util.Objects;

/*    */
/*    */
@TableName("screen")
/*    */ public class Screen {
    /*    */   private Integer id;
    /*    */   private String merchant;
    /*    */   private Integer width;
    /*    */   private Integer height;
    /*    */   private Integer radius;
    /*    */   private Integer padding;
    /*    */   private String bgColor;
    private String md;
    private Integer iconWidth;
    private String iconUrl;
    private String iconPositionY;
    private String iconPositionX;
    private Integer iconOffset;
    private String createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Screen)) return false;
        com.bss.entity.Screen other = (com.bss.entity.Screen) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$width = getWidth(), other$width = other.getWidth();
        if (!Objects.equals(this$width, other$width)) return false;
        Object this$height = getHeight(), other$height = other.getHeight();
        if (!Objects.equals(this$height, other$height)) return false;
        Object this$radius = getRadius(), other$radius = other.getRadius();
        if (!Objects.equals(this$radius, other$radius)) return false;
        Object this$padding = getPadding(), other$padding = other.getPadding();
        if (!Objects.equals(this$padding, other$padding)) return false;
        Object this$bgColor = getBgColor(), other$bgColor = other.getBgColor();
        if (!Objects.equals(this$bgColor, other$bgColor)) return false;
        Object this$md = getMd(), other$md = other.getMd();
        if (!Objects.equals(this$md, other$md)) return false;
        Object this$iconWidth = getIconWidth(), other$iconWidth = other.getIconWidth();
        if (!Objects.equals(this$iconWidth, other$iconWidth))
            return false;
        Object this$iconUrl = getIconUrl(), other$iconUrl = other.getIconUrl();
        if (!Objects.equals(this$iconUrl, other$iconUrl)) return false;
        Object this$iconPositionY = getIconPositionY(), other$iconPositionY = other.getIconPositionY();
        if (!Objects.equals(this$iconPositionY, other$iconPositionY))
            return false;
        Object this$iconPositionX = getIconPositionX(), other$iconPositionX = other.getIconPositionX();
        if (!Objects.equals(this$iconPositionX, other$iconPositionX))
            return false;
        Object this$iconOffset = getIconOffset(), other$iconOffset = other.getIconOffset();
        if (!Objects.equals(this$iconOffset, other$iconOffset))
            return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Screen;
    }


    public String toString() {
        return "Screen(id=" + getId() + ", merchant=" + getMerchant() + ", width=" + getWidth() + ", height=" + getHeight() + ", radius=" + getRadius() + ", padding=" + getPadding() + ", bgColor=" + getBgColor() + ", md=" + getMd() + ", iconWidth=" + getIconWidth() + ", iconUrl=" + getIconUrl() + ", iconPositionY=" + getIconPositionY() + ", iconPositionX=" + getIconPositionX() + ", iconOffset=" + getIconOffset() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    /*    */
    /* 13 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getMerchant() {
        /* 17 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public Integer getWidth() {
        /* 19 */
        return this.width;
        /*    */
    }

    public void setWidth(Integer width) {
        this.width = width;
    }

    public Integer getHeight() {
        /* 21 */
        return this.height;
        /*    */
    }

    public void setHeight(Integer height) {
        this.height = height;
    }

    public Integer getRadius() {
        /* 23 */
        return this.radius;
        /*    */
    }

    public void setRadius(Integer radius) {
        this.radius = radius;
    }

    public Integer getPadding() {
        /* 25 */
        return this.padding;
        /*    */
    }

    public void setPadding(Integer padding) {
        this.padding = padding;
    }

    public String getBgColor() {
        /* 27 */
        return this.bgColor;
        /*    */
    }

    public void setBgColor(String bgColor) {
        this.bgColor = bgColor;
    }

    public String getMd() {
        /* 29 */
        return this.md;
        /*    */
    }

    public void setMd(String md) {
        this.md = md;
    }

    public Integer getIconWidth() {
        /* 31 */
        return this.iconWidth;
        /*    */
    }

    public void setIconWidth(Integer iconWidth) {
        this.iconWidth = iconWidth;
    }

    public String getIconUrl() {
        /* 33 */
        return this.iconUrl;
        /*    */
    }

    public void setIconUrl(String iconUrl) {
        this.iconUrl = iconUrl;
    }

    public String getIconPositionY() {
        /* 35 */
        return this.iconPositionY;
        /*    */
    }

    public void setIconPositionY(String iconPositionY) {
        this.iconPositionY = iconPositionY;
    }

    public String getIconPositionX() {
        /* 37 */
        return this.iconPositionX;
        /*    */
    }

    public void setIconPositionX(String iconPositionX) {
        this.iconPositionX = iconPositionX;
    }

    public Integer getIconOffset() {
        /* 39 */
        return this.iconOffset;
        /*    */
    }

    public void setIconOffset(Integer iconOffset) {
        this.iconOffset = iconOffset;
    }

    public String getCreateTime() {
        /* 41 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Screen.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */