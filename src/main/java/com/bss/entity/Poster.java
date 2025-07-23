/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.*;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/*    */
@TableName("poster")
/*    */ public class Poster implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private Long merchant;
    /*    */   private String mainImage;
    /*    */   private Integer imgW;
    /*    */   private Integer imgH;
    /*    */   private Integer qrW;
    /*    */   private Integer qrH;
    private Integer qrX;
    private Integer qrY;
    private String qrColor;
    private Boolean isHyaline;
    private Integer state;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Poster)) return false;
        com.bss.entity.Poster other = (com.bss.entity.Poster) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$mainImage = getMainImage(), other$mainImage = other.getMainImage();
        if (!Objects.equals(this$mainImage, other$mainImage))
            return false;
        Object this$imgW = getImgW(), other$imgW = other.getImgW();
        if (!Objects.equals(this$imgW, other$imgW)) return false;
        Object this$imgH = getImgH(), other$imgH = other.getImgH();
        if (!Objects.equals(this$imgH, other$imgH)) return false;
        Object this$qrW = getQrW(), other$qrW = other.getQrW();
        if (!Objects.equals(this$qrW, other$qrW)) return false;
        Object this$qrH = getQrH(), other$qrH = other.getQrH();
        if (!Objects.equals(this$qrH, other$qrH)) return false;
        Object this$qrX = getQrX(), other$qrX = other.getQrX();
        if (!Objects.equals(this$qrX, other$qrX)) return false;
        Object this$qrY = getQrY(), other$qrY = other.getQrY();
        if (!Objects.equals(this$qrY, other$qrY)) return false;
        Object this$qrColor = getQrColor(), other$qrColor = other.getQrColor();
        if (!Objects.equals(this$qrColor, other$qrColor)) return false;
        Object this$isHyaline = getIsHyaline(), other$isHyaline = other.getIsHyaline();
        if (!Objects.equals(this$isHyaline, other$isHyaline))
            return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Poster;
    }


    public String toString() {
        return "Poster(id=" + getId() + ", merchant=" + getMerchant() + ", mainImage=" + getMainImage() + ", imgW=" + getImgW() + ", imgH=" + getImgH() + ", qrW=" + getQrW() + ", qrH=" + getQrH() + ", qrX=" + getQrX() + ", qrY=" + getQrY() + ", qrColor=" + getQrColor() + ", isHyaline=" + getIsHyaline() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    /*    */
    /* 13 */
    public void setId(Integer id) {
        this.id = id;
    }

    public Long getMerchant() {
        /* 18 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(Long merchant) {
        this.merchant = merchant;
    }

    public String getMainImage() {
        /* 20 */
        return this.mainImage;
        /*    */
    }

    public void setMainImage(String mainImage) {
        this.mainImage = mainImage;
    }

    public Integer getImgW() {
        /* 22 */
        return this.imgW;
        /*    */
    }

    public void setImgW(Integer imgW) {
        this.imgW = imgW;
    }

    public Integer getImgH() {
        /* 24 */
        return this.imgH;
        /*    */
    }

    public void setImgH(Integer imgH) {
        this.imgH = imgH;
    }

    public Integer getQrW() {
        /* 26 */
        return this.qrW;
        /*    */
    }

    public void setQrW(Integer qrW) {
        this.qrW = qrW;
    }

    public Integer getQrH() {
        /* 28 */
        return this.qrH;
        /*    */
    }

    public void setQrH(Integer qrH) {
        this.qrH = qrH;
    }

    public Integer getQrX() {
        /* 30 */
        return this.qrX;
        /*    */
    }

    public void setQrX(Integer qrX) {
        this.qrX = qrX;
    }

    public Integer getQrY() {
        /* 32 */
        return this.qrY;
        /*    */
    }

    public void setQrY(Integer qrY) {
        this.qrY = qrY;
    }

    public String getQrColor() {
        /* 34 */
        return this.qrColor;
        /*    */
    }

    public void setQrColor(String qrColor) {
        this.qrColor = qrColor;
    }

    public Boolean getIsHyaline() {
        /* 36 */
        return this.isHyaline;
        /*    */
    }

    public void setIsHyaline(Boolean isHyaline) {
        this.isHyaline = isHyaline;
    }

    public Integer getState() {
        /* 38 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }

    /*    */
    public Date getCreateTime() {
        /* 41 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Poster.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */