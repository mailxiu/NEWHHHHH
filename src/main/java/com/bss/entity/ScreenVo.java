/*    */
package com.bss.entity;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
/*    */ public class ScreenVo implements Serializable {
    /*    */   private Integer width;
    /*    */   private Integer height;
    /*    */   private Integer radius;
    /*    */   private String bgColor;
    private String md;
    private String iconUrl;
    private String iconPositionY;
    private String iconPositionX;
    private Integer iconOffset;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ScreenVo)) return false;
        com.bss.entity.ScreenVo other = (com.bss.entity.ScreenVo) o;
        if (!other.canEqual(this)) return false;
        Object this$width = getWidth(), other$width = other.getWidth();
        if (!Objects.equals(this$width, other$width)) return false;
        Object this$height = getHeight(), other$height = other.getHeight();
        if (!Objects.equals(this$height, other$height)) return false;
        Object this$radius = getRadius(), other$radius = other.getRadius();
        if (!Objects.equals(this$radius, other$radius)) return false;
        Object this$bgColor = getBgColor(), other$bgColor = other.getBgColor();
        if (!Objects.equals(this$bgColor, other$bgColor)) return false;
        Object this$md = getMd(), other$md = other.getMd();
        if (!Objects.equals(this$md, other$md)) return false;
        Object this$iconUrl = getIconUrl(), other$iconUrl = other.getIconUrl();
        if (!Objects.equals(this$iconUrl, other$iconUrl)) return false;
        Object this$iconPositionY = getIconPositionY(), other$iconPositionY = other.getIconPositionY();
        if (!Objects.equals(this$iconPositionY, other$iconPositionY))
            return false;
        Object this$iconPositionX = getIconPositionX(), other$iconPositionX = other.getIconPositionX();
        if (!Objects.equals(this$iconPositionX, other$iconPositionX))
            return false;
        Object this$iconOffset = getIconOffset(), other$iconOffset = other.getIconOffset();
        return !(!Objects.equals(this$iconOffset, other$iconOffset));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ScreenVo;
    }


    public String toString() {
        return "ScreenVo(width=" + getWidth() + ", height=" + getHeight() + ", radius=" + getRadius() + ", bgColor=" + getBgColor() + ", md=" + getMd() + ", iconUrl=" + getIconUrl() + ", iconPositionY=" + getIconPositionY() + ", iconPositionX=" + getIconPositionX() + ", iconOffset=" + getIconOffset() + ")";
    }

    /*    */
    /*    */
    public Integer getWidth() {
        /* 13 */
        return this.width;
        /*    */
    }

    /*    */
    /* 10 */
    public void setWidth(Integer width) {
        this.width = width;
    }

    public Integer getHeight() {
        /* 15 */
        return this.height;
        /*    */
    }

    public void setHeight(Integer height) {
        this.height = height;
    }

    public Integer getRadius() {
        /* 17 */
        return this.radius;
        /*    */
    }

    public void setRadius(Integer radius) {
        this.radius = radius;
    }

    public String getBgColor() {
        /* 19 */
        return this.bgColor;
        /*    */
    }

    public void setBgColor(String bgColor) {
        this.bgColor = bgColor;
    }

    public String getMd() {
        /* 21 */
        return this.md;
        /*    */
    }

    public void setMd(String md) {
        this.md = md;
    }

    public String getIconUrl() {
        /* 23 */
        return this.iconUrl;
        /*    */
    }

    public void setIconUrl(String iconUrl) {
        this.iconUrl = iconUrl;
    }

    public String getIconPositionY() {
        /* 25 */
        return this.iconPositionY;
        /*    */
    }

    public void setIconPositionY(String iconPositionY) {
        this.iconPositionY = iconPositionY;
    }

    public String getIconPositionX() {
        /* 27 */
        return this.iconPositionX;
        /*    */
    }

    public void setIconPositionX(String iconPositionX) {
        this.iconPositionX = iconPositionX;
    }

    public Integer getIconOffset() {
        /* 29 */
        return this.iconOffset;
        /*    */
    }

    public void setIconOffset(Integer iconOffset) {
        this.iconOffset = iconOffset;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ScreenVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */