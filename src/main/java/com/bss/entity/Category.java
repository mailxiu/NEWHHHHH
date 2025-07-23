/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("category")
/*    */ public class Category implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String merchant;
    /*    */   private Integer sort;
    /*    */   private String name;
    private String image;
    private Integer purchase;
    private String notes;
    private Integer state;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Category)) return false;
        com.bss.entity.Category other = (com.bss.entity.Category) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$image = getImage(), other$image = other.getImage();
        if (!Objects.equals(this$image, other$image)) return false;
        Object this$purchase = getPurchase(), other$purchase = other.getPurchase();
        if (!Objects.equals(this$purchase, other$purchase)) return false;
        Object this$notes = getNotes(), other$notes = other.getNotes();
        if (!Objects.equals(this$notes, other$notes)) return false;
        Object this$state = getState(), other$state = other.getState();
        return !(!Objects.equals(this$state, other$state));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Category;
    }


    public String toString() {
        return "Category(id=" + getId() + ", merchant=" + getMerchant() + ", sort=" + getSort() + ", name=" + getName() + ", image=" + getImage() + ", purchase=" + getPurchase() + ", notes=" + getNotes() + ", state=" + getState() + ")";
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

    public String getMerchant() {
        /* 19 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public Integer getSort() {
        /* 21 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public String getName() {
        /* 23 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImage() {
        /* 25 */
        return this.image;
        /*    */
    }

    public void setImage(String image) {
        this.image = image;
    }

    public Integer getPurchase() {
        /* 27 */
        return this.purchase;
        /*    */
    }

    public void setPurchase(Integer purchase) {
        this.purchase = purchase;
    }

    public String getNotes() {
        /* 29 */
        return this.notes;
        /*    */
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public Integer getState() {
        /* 31 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Category.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */