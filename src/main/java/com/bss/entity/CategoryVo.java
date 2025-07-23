/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
/*    */
@TableName("category")
/*    */ public class CategoryVo implements Serializable {
    /*    */   private Integer id;
    /*    */   private String name;
    /*    */   private Integer sort;
    /*    */   private String image;
    /*    */   private Integer state;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.CategoryVo)) return false;
        com.bss.entity.CategoryVo other = (com.bss.entity.CategoryVo) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$image = getImage(), other$image = other.getImage();
        if (!Objects.equals(this$image, other$image)) return false;
        Object this$state = getState(), other$state = other.getState();
        return !(!Objects.equals(this$state, other$state));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.CategoryVo;
    }


    public String toString() {
        return "CategoryVo(id=" + getId() + ", name=" + getName() + ", sort=" + getSort() + ", image=" + getImage() + ", state=" + getState() + ")";
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

    public String getName() {
        /* 17 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getSort() {
        /* 19 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public String getImage() {
        /* 21 */
        return this.image;
        /*    */
    }

    public void setImage(String image) {
        this.image = image;
    }

    public Integer getState() {
        /* 23 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\CategoryVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */