/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/*    */
@TableName("record")
/*    */ public class Record implements Serializable {
    private static final long serialVersionUID = 1L;
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String merchant;
    /*    */   private String oid;
    /*    */   private String uid;
    /*    */   private Integer cid;
    /*    */   private String name;
    /*    */   private String image;
    /*    */   private Double points;
    private String code;
    private String qrCode;
    private String checkCode;
    private Integer sale;
    private String state;
    private Integer exportState;
    private Date updateTime;
    private String createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Record)) return false;
        com.bss.entity.Record other = (com.bss.entity.Record) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$oid = getOid(), other$oid = other.getOid();
        if (!Objects.equals(this$oid, other$oid)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if (!Objects.equals(this$uid, other$uid)) return false;
        Object this$cid = getCid(), other$cid = other.getCid();
        if (!Objects.equals(this$cid, other$cid)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$image = getImage(), other$image = other.getImage();
        if (!Objects.equals(this$image, other$image)) return false;
        Object this$points = getPoints(), other$points = other.getPoints();
        if (!Objects.equals(this$points, other$points)) return false;
        Object this$code = getCode(), other$code = other.getCode();
        if (!Objects.equals(this$code, other$code)) return false;
        Object this$qrCode = getQrCode(), other$qrCode = other.getQrCode();
        if (!Objects.equals(this$qrCode, other$qrCode)) return false;
        Object this$checkCode = getCheckCode(), other$checkCode = other.getCheckCode();
        if (!Objects.equals(this$checkCode, other$checkCode))
            return false;
        Object this$sale = getSale(), other$sale = other.getSale();
        if (!Objects.equals(this$sale, other$sale)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$exportState = getExportState(), other$exportState = other.getExportState();
        if (!Objects.equals(this$exportState, other$exportState))
            return false;
        Object this$updateTime = getUpdateTime(), other$updateTime = other.getUpdateTime();
        if (!Objects.equals(this$updateTime, other$updateTime))
            return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Record;
    }


    public String toString() {
        return "Record(id=" + getId() + ", merchant=" + getMerchant() + ", oid=" + getOid() + ", uid=" + getUid() + ", cid=" + getCid() + ", name=" + getName() + ", image=" + getImage() + ", points=" + getPoints() + ", code=" + getCode() + ", qrCode=" + getQrCode() + ", checkCode=" + getCheckCode() + ", sale=" + getSale() + ", state=" + getState() + ", exportState=" + getExportState() + ", updateTime=" + getUpdateTime() + ", createTime=" + getCreateTime() + ")";
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

    public String getMerchant() {
        /* 18 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public String getOid() {
        /* 20 */
        return this.oid;
        /*    */
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public String getUid() {
        /* 22 */
        return this.uid;
        /*    */
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public Integer getCid() {
        /* 24 */
        return this.cid;
        /*    */
    }

    public void setCid(Integer cid) {
        this.cid = cid;
    }

    public String getName() {
        /* 26 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImage() {
        /* 28 */
        return this.image;
        /*    */
    }

    public void setImage(String image) {
        this.image = image;
    }

    public Double getPoints() {
        /* 30 */
        return this.points;
        /*    */
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public String getCode() {
        /* 32 */
        return this.code;
        /*    */
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getQrCode() {
        /* 34 */
        return this.qrCode;
        /*    */
    }

    public void setQrCode(String qrCode) {
        this.qrCode = qrCode;
    }

    public String getCheckCode() {
        /* 36 */
        return this.checkCode;
        /*    */
    }

    public void setCheckCode(String checkCode) {
        this.checkCode = checkCode;
    }

    public Integer getSale() {
        /* 38 */
        return this.sale;
        /*    */
    }

    public void setSale(Integer sale) {
        this.sale = sale;
    }

    public String getState() {
        /* 40 */
        return this.state;
        /*    */
    }

    public void setState(String state) {
        this.state = state;
    }

    public Integer getExportState() {
        /* 42 */
        return this.exportState;
        /*    */
    }

    public void setExportState(Integer exportState) {
        this.exportState = exportState;
    }

    public Date getUpdateTime() {
        /* 44 */
        return this.updateTime;
        /*    */
    }

    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }

    public String getCreateTime() {
        /* 46 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Record.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */